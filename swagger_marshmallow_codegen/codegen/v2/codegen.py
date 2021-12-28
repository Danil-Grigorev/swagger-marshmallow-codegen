from __future__ import annotations
import typing as t
import keyword
import logging
from collections import namedtuple
from collections import defaultdict
from collections import OrderedDict
from functools import partial
from prestring import PreString
from prestring.python import Module
from prestring.utils import LazyFormat, LazyArgumentsAndKeywords, LazyKeywords
from dictknife import deepmerge
from swagger_marshmallow_codegen.langhelpers import (
    LazyCallString,
    titleize,
    clsname_from_path,
)
from swagger_marshmallow_codegen.constants import (
    X_MARSHMALLOW_NAME,
    X_MARSHMALLOW_INLINE,
)
from ..context import Context
from ..config import ConfigDict
from .accessor import Accessor
from marshmallow import Schema

if t.TYPE_CHECKING:
    from swagger_marshmallow_codegen.resolver import Resolver
    from ..context import ContextFactory, InputData, OutputData

logger = logging.getLogger(__name__)
NAME_MARKER = X_MARSHMALLOW_NAME

PathInfo = namedtuple("PathInfo", "info, required")

schema_params = Schema().__dict__

class CodegenError(Exception):
    pass


class SchemaWriter:
    extra_schema_module = "swagger_marshmallow_codegen.schema"

    @classmethod
    def override(cls, *, extra_schema_module=None):
        return partial(cls, extra_schema_module=extra_schema_module)

    def __init__(self, accessor: Accessor, schema_class, *, extra_schema_module=None):
        self.accessor = accessor
        self.schema_class = schema_class
        self.arrived = set()
        self.extra_schema_module = (
            extra_schema_module or self.__class__.extra_schema_module
        )

    @property
    def resolver(self) -> Resolver:
        return self.accessor.resolver

    def _get_caller(
        self,
        c,
        d,
        name,
        caller_name,
        field_class_name,
        field,
        *,
        opts,
        many: bool = False
    ):
        # {"properties": {"memo": {"$ref": "#/definitions/Memo"}}}
        # name="memo", caller_name="fields.Nested", field_class_name="Memo"
        if many:
            self.accessor.update_option_on_property(c, field, opts)
            field = field["items"]
            if self.resolver.has_ref(field):
                field_class_name, field = self.resolver.resolve_ref_definition(
                    c, d, field, level=1
                )
                # finding original definition
                if self.resolver.has_ref(field):
                    ref_name, field = self.resolver.resolve_ref_definition(c, d, field)
                    if ref_name is None:
                        raise CodegenError("ref: %r is not found", field["$ref"])

            caller_name = self.accessor.resolver.resolve_caller_name(c, name, field)
            if caller_name is None:
                raise CodegenError(
                    "matched field class is not found. name=%r", name,
                )

            opts.pop("many", None)
            opts = {k: repr(v) for k, v in opts.items()}
            return LazyFormat(
                "fields.List({})",
                LazyArgumentsAndKeywords(
                    [
                        self._get_caller(
                            c,
                            d,
                            name,
                            caller_name,
                            field_class_name,
                            field,
                            opts={},
                            many=self.resolver.has_many(field),
                        )
                    ],
                    opts,
                ),
            )

        if field is None:
            opts = {k: repr(v) for k, v in opts.items()}
            if caller_name == "fields.Nested":
                return LazyFormat(
                    "fields.Nested({})",
                    LazyArgumentsAndKeywords([c.use_relative(field_class_name)], opts,),
                )
            else:
                return LazyFormat("{}({})", caller_name, LazyKeywords(opts))
        elif self.resolver.has_nested(d, field) and field_class_name:
            logger.debug("      nested: %s, %s", caller_name, field_class_name)
            self.accessor.update_option_on_property(c, field, opts)
            opts = {k: repr(v) for k, v in opts.items()}
            return LazyFormat(
                "fields.Nested({})",
                LazyArgumentsAndKeywords([c.use_relative(field_class_name)], opts,),
            )
        elif caller_name == "fields.Dict":
            self.accessor.update_option_on_property(c, field, opts)
            try:
                field = field["additionalProperties"]
            except KeyError:
                caller_name = self.accessor.resolver.resolve_caller_name(c, name, field)
                return LazyFormat(
                    "fields.Dict(keys=fields.String(), values={})",
                    caller_name,
                    LazyKeywords(opts),
                )

            if self.resolver.has_ref(field):
                field_class_name, field = self.resolver.resolve_ref_definition(
                    c, d, field, level=1
                )
                # finding original definition
                if self.resolver.has_ref(field):
                    ref_name, field = self.resolver.resolve_ref_definition(c, d, field)
                    if ref_name is None:
                        raise CodegenError("ref: %r is not found", field["$ref"])

            caller_name = self.accessor.resolver.resolve_caller_name(c, name, field)
            if caller_name is None:
                raise CodegenError(
                    "matched field class is not found. name=%r", name,
                )

            opts = {k: repr(v) for k, v in opts.items()}
            return LazyFormat(
                "fields.Dict(keys=fields.String(), values={})",
                LazyArgumentsAndKeywords(
                    [
                        self._get_caller(
                            c,
                            d,
                            name,
                            caller_name,
                            field_class_name,
                            field.get("additionalProperties"),
                            opts={},
                            many=self.resolver.has_many(field),
                        )
                    ],
                    opts,
                ),
            )

        else:
            self.accessor.update_option_on_property(c, field, opts)
            opts = {k: repr(v) for k, v in opts.items()}
            if caller_name == "fields.Nested":
                caller_name = "fields.Field"
            return LazyFormat("{}({})", caller_name, LazyKeywords(opts))

    def write_field_one(
        self, c, d, schema_name, definition, name, field, opts, *, many: bool = False
    ):
        field_class_name = None
        if self.resolver.has_ref(field):
            field_class_name, field = self.resolver.resolve_ref_definition(
                c, d, field, level=1
            )
            if self.resolver.has_many(field):
                return self.write_field_one(
                    c, d, field_class_name, definition, name, field, opts, many=True
                )

            # finding original definition
            if self.resolver.has_ref(field):
                ref_name, field = self.resolver.resolve_ref_definition(c, d, field)
                if self.resolver.has_many(field):
                    return self.write_field_one(
                        c, d, field_class_name, definition, name, field, opts, many=True
                    )
                if ref_name is None:
                    raise CodegenError("ref: %r is not found", field["$ref"])

        logger.debug("      field: %s", lazy_json_dump(field))
        caller_name = self.accessor.resolver.resolve_caller_name(c, name, field)
        if caller_name is None:
            raise CodegenError(
                "matched field class is not found. name=%r, schema=%r",
                name,
                schema_name,
            )

        normalized_name = self.resolver.resolve_normalized_name(name)
        if normalized_name != name:
            opts["data_key"] = name
        if keyword.iskeyword(normalized_name) or normalized_name in schema_params:
            opts["data_key"] = normalized_name
            normalized_name = normalized_name + "_"

        # logger.info("  write field: write %s, field=%s", name, caller_name)
        c.m.stmt(
            "{} = {}",
            normalized_name,
            self._get_caller(
                c, d, name, caller_name, field_class_name, field, opts=opts, many=many
            ),
        )

        return normalized_name

    def write_primitive_schema(self, c, d, clsname, definition, many=False):
        c.im.from_(self.extra_schema_module, "PrimitiveValueSchema")
        with c.m.class_(clsname, "PrimitiveValueSchema"):
            with c.m.class_("schema_class", self.schema_class):
                if many or self.resolver.has_many(definition):
                    definition["type"] = "array"
                    self.write_field_one(
                        c, d, clsname, {}, "value", definition, {}, many=True
                    )
                else:
                    self.write_field_one(c, d, clsname, {}, "value", definition, {})

    def write_schema(
        self, c, d, clsname, definition, force=False, meta_writer=None, many=False, base_classes=None,
    ):
        field_names = []
        if not force and clsname in self.arrived:
            return field_names
        description = definition and definition.get('description', None)
        if not base_classes:
            base_classes = [self.schema_class]
        self.arrived.add(clsname)
        if self.resolver.has_ref(definition):
            ref_name, ref_definition = self.resolver.resolve_ref_definition(
                c, d, definition
            )
            if ref_name is None:
                raise CodegenError("$ref %r is not found", definition["$ref"])
            elif "items" in ref_definition:
                # work around
                many = True
                items = ref_definition["items"]
                if self.resolver.has_ref(items):
                    _, items = self.resolver.resolve_ref_definition(
                        c, d, ref_definition["items"]
                    )
                if not self.resolver.has_schema(d, items):
                    self.write_primitive_schema(
                        c, d, clsname, ref_definition, many=many
                    )
                    return field_names
                else:
                    field_names.extend(self.write_schema(c, d, ref_name, items))
                    base_classes = [ref_name]
            else:
                if not self.resolver.has_schema(d, ref_definition):
                    self.write_primitive_schema(
                        c, d, clsname, ref_definition, many=many
                    )
                    return field_names
                field_names.extend(self.write_schema(c, d, ref_name, ref_definition))
                base_classes = [ref_name]
        elif self.resolver.has_allof(definition):
            ref_list, ref_definition = self.resolver.resolve_allof_definition(
                c, d, definition
            )
            definition = deepmerge(ref_definition, definition)
            if ref_list:
                base_classes = []
                for ref_name, ref_definition in ref_list:
                    c.relative_import(ref_name)
                    if ref_name is None:
                        raise CodegenError(
                            "$ref %r is not found", ref_definition
                        )  # xxx
                    else:
                        field_names.extend(self.write_schema(c, d, ref_name, ref_definition))
                        base_classes.append(ref_name)

        # supporting additional properties
        if (
            hasattr(definition.get("additionalProperties"), "keys")
            and base_classes[0] == self.schema_class
        ):
            c.from_(self.extra_schema_module, "AdditionalPropertiesSchema")
            base_classes[0] = "AdditionalPropertiesSchema"

        if "properties" not in definition and (
            "object" != definition.get("type", "object") and "items" not in definition
        ):
            self.write_primitive_schema(c, d, clsname, definition, many=many)
            return field_names

        if "items" in definition:
            many = True
            if not self.resolver.has_ref(definition["items"]):
                self.write_primitive_schema(c, d, clsname, definition, many=many)
                return field_names
            else:
                ref_name, ref_definition = self.resolver.resolve_ref_definition(
                    c, d, definition["items"]
                )
                if ref_name is None:
                    self.write_primitive_schema(
                        c, d, clsname, definition, many=many
                    )
                    return field_names
                else:
                    field_names.extend(self.write_schema(c, d, ref_name, ref_definition))
                    base_classes = [ref_name]

        with c.m.class_(clsname, bases=base_classes):
            if description:
                c.m.stmt('"""')
                for line in (
                    description.rstrip("\n").split("\n")
                ):
                    c.m.stmt(line)
                c.m.stmt('"""')
                c.m.stmt("")

            if meta_writer is not None:
                meta_writer(c.m)

            if many or self.resolver.has_many(definition):
                with c.m.def_("__init__", "self", "*args", "**kwargs"):
                    c.m.stmt("kwargs['many'] = True")
                    c.m.stmt("super().__init__(*args, **kwargs)")

            opts = defaultdict(OrderedDict)
            self.accessor.update_options_pre_properties(definition, opts)

            properties = self.accessor.properties(definition)
            need_pass_statement = False
            if not properties and not many:
                need_pass_statement = True
            else:
                for name, field in properties.items():
                    name = str(name)
                    field_names.append(self.write_field_one(
                        c,
                        d,
                        clsname,
                        definition,
                        name,
                        field,
                        opts[name],
                        many=self.resolver.has_many(field),
                    ))

            # supporting additional properties
            subdef = definition.get("additionalProperties")
            if subdef and hasattr(subdef, "keys"):
                need_pass_statement = False
                c.m.sep()
                subdef = definition["additionalProperties"]
                with c.m.class_("Meta"):
                    if self.resolver.has_ref(subdef):
                        ref_name, _ = self.resolver.resolve_ref_definition(c, d, subdef)
                        if ref_name is None:
                            raise CodegenError("$ref %r is not found", subdef["$ref"])
                        self.write_field_one(
                            c,
                            d,
                            ref_name,
                            {},
                            "additional_field",
                            subdef,
                            OrderedDict(),
                        )
                    else:
                        self.write_field_one(
                            c,
                            d,
                            "",
                            subdef,
                            "additional_field",
                            subdef,
                            {},
                            many=self.resolver.has_many(subdef),
                        )

            elif base_classes[0] != "AdditionalPropertiesSchema":
                unknown_value = None
                v = definition.get("additionalProperties")
                if v is True:
                    unknown_value = "INCLUDE"
                elif v is False:
                    unknown_value = "RAISE"
                else:  # None
                    if (
                        self.accessor.config.get("additional_properties_default", False)
                        is True
                    ):
                        unknown_value = "INCLUDE"
                    elif self.accessor.config.get("explicit", False):
                        # marshmallow's default
                        unknown_value = "RAISE"

                if unknown_value is not None:
                    c.m.sep()
                    with c.m.class_("Meta"):
                        c.from_("marshmallow", unknown_value)
                        c.m.stmt("unknown = {}", unknown_value)
                    need_pass_statement = False

            if need_pass_statement:
                c.m.stmt("pass")
        return field_names


class DefinitionsSchemaWriter:
    def __init__(self, accessor, schema_writer):
        self.accessor = accessor
        self.schema_writer = schema_writer

    @property
    def resolver(self) -> Resolver:
        return self.accessor.resolver

    @property
    def config(self) -> ConfigDict:
        return self.accessor.config

    def write(self, d: InputData, *, context_factory: ContextFactory) -> None:
        part = self.__class__.__name__
        for schema_name, definition in self.accessor.definitions(d):
            if not self.config.get(
                "emit_schema_even_primitive_type", False
            ) and not self.resolver.has_schema(d, definition):
                logger.info("write schema: skip %s", schema_name)
                continue

            c = context_factory(
                definition.get(X_MARSHMALLOW_INLINE) or schema_name, part=part,
            )
            clsname = self.resolver.resolve_schema_name(schema_name)
            logger.info("write schema: write %s", schema_name)
            self.schema_writer.write_schema(c, d, clsname, definition)


class PathsSchemaWriter:
    OVERRIDE_NAME_MARKER = NAME_MARKER

    def __init__(self, accessor, schema_writer):
        self.accessor = accessor
        self.schema_writer = schema_writer

    @property
    def resolver(self) -> Resolver:
        return self.accessor.resolver

    def get_lazy_clsname(self, path):
        return PreString(clsname_from_path(path))

    def write(self, d: InputData, *, context_factory: ContextFactory) -> None:
        part = self.__class__.__name__
        for path, methods in self.accessor.paths(d):
            sc = context_factory(path, part=part)
            lazy_clsname = self.get_lazy_clsname(path)
            toplevel_parameters = self.accessor.parameters(methods)
            if self.OVERRIDE_NAME_MARKER in methods:
                lazy_clsname.pop()
                lazy_clsname.append(methods[self.OVERRIDE_NAME_MARKER])
            for method, definition in self.accessor.methods(methods):
                description = definition.get('definition', None) or definition.get('summary', None)
                ssc = sc.new_child()
                path_info = self.build_path_info(
                    sc,
                    d,
                    toplevel_parameters,
                    self.accessor.parameters(definition),
                )
                body_info = self.build_body_info(
                    sc,
                    d,
                    self.accessor.requestBody(definition)
                )
                info = sorted(path_info.info.items())
                method_bases = []
                method_kwargs = []
                paths = ['Path'], filter(lambda section: section[0] == 'path', info)
                queries = ['Query'], filter(lambda section: section[0] == 'query', info)
                json_bodies = ['Body'], sorted(body_info.info.items())

                bodies = filter(lambda section: section[0] == 'body', info)
                for section, properties in bodies:
                    name = LazyFormat("{}{}{}", lazy_clsname, titleize(method), titleize(section))
                    method_bases.append(name)
                    data = next(iter(properties.values()))["schema"]
                    data["description"] = description
                    self.schema_writer.write_schema(
                        ssc, d, name, data, force=True
                    )

                for bases, section_type in [json_bodies, queries, paths]:
                    for section, properties in section_type:
                        name = LazyFormat("{}{}{}", lazy_clsname, titleize(method), titleize(section))
                        method_bases.append(name)
                        for props_data in properties.values():
                            if props_data.get("schema", None):
                                props_data['type'] = props_data.pop('schema')['type']
                        data = {
                            "properties": properties,
                            "required": path_info.required[section],
                            "description": description,
                        }
                        bases = bases if self.accessor.config.get('emit_model', False) else []
                        method_kwargs.extend(self.schema_writer.write_schema(
                            ssc, d, name, data, base_classes=bases
                        ))

                if self.accessor.config.get('emit_model', False):
                    method_bases.append("Model")
                    with sc.m.class_(LazyFormat("{}{}", lazy_clsname, titleize(method)), bases=method_bases):
                        sc.m.stmt("_method = '{}'".format(method))
                        sc.m.stmt("_url = '{}'".format(path))
                        kwargs = ['{kwarg}=None'.format(kwarg=kwarg) for kwarg in method_kwargs]
                        if kwargs:
                            with sc.m.def_('__init__', 'self', '*args', *kwargs, '**kwargs'):
                                sc.m.stmt('super().__init__(*args, **self._strip(locals()), **kwargs)')


    def build_path_info(
        self,
        c: Context,
        fulldata: t.Dict[str, t.Any],
        *paramaters_set: t.List[t.Dict[str, t.Any]]
    ) -> PathInfo:
        info = defaultdict(OrderedDict)
        required = defaultdict(list)
        for parameters in paramaters_set:
            for p in parameters:
                if self.resolver.has_ref(p):
                    _, p = self.resolver.resolve_ref_definition(c, fulldata, p)
                name = p.get("name")
                section = p.get("in")
                info[section][name] = p
                if p.get("required"):
                    required[section].append(name)
        return PathInfo(info=info, required=required)

    def build_body_info(
        self,
        c: Context,
        fulldata: t.Dict[str, t.Any],
        *paramaters_set: t.List[t.Dict[str, t.Any]]
    ) -> PathInfo:
        info = defaultdict(OrderedDict)
        required = defaultdict(list)
        for parameters in paramaters_set:
            if not parameters:
                continue
            schema = parameters['content']['application/json']['schema']
            if schema.get('items', None) and self.resolver.has_ref(schema['items']):
                _, schema = self.resolver.resolve_ref_definition(c, fulldata, schema['items'])
            properties = schema['properties']
            for name in properties:
                info['body'][name] = properties[name]
                if properties[name].get('required', False):
                    required['body'].append(name)
        return PathInfo(info=info, required=required)


class ResponsesSchemaWriter:
    OVERRIDE_NAME_MARKER = NAME_MARKER

    def __init__(self, accessor, schema_writer):
        self.accessor = accessor
        self.schema_writer = schema_writer

    @property
    def resolver(self) -> Resolver:
        return self.accessor.resolver

    # todo: move
    def get_lazy_clsname(self, path):
        return PreString(clsname_from_path(path))

    def write(self, d: InputData, *, context_factory: ContextFactory) -> None:
        part = self.__class__.__name__
        for path, methods in self.accessor.paths(d):
            lazy_clsname = self.get_lazy_clsname(path)
            sc = context_factory(path, part=part)
            found = False
            with sc.m.class_(LazyFormat("{}Output", lazy_clsname)):
                if self.OVERRIDE_NAME_MARKER in methods:
                    lazy_clsname.pop()
                    lazy_clsname.append(methods[self.OVERRIDE_NAME_MARKER])
                for method, definition in self.accessor.methods(methods):
                    for status, definition in self.accessor.responses(definition):
                        if self.resolver.has_ref(definition):
                            _, definition = self.resolver.resolve_ref_definition(
                                sc, d, definition
                            )
                        if "schema" in definition:
                            found = True
                            clsname = titleize(method) + status
                            schema_definition = definition["schema"]

                            def meta(m):
                                if "description" in definition:
                                    m.stmt('"""{}"""'.format(definition["description"]))

                            self.schema_writer.write_schema(
                                sc,
                                d,
                                clsname,
                                schema_definition,
                                force=True,
                                meta_writer=meta,
                            )
            if not found:
                sc.m.clear()


class Codegen:
    schema_class_path = "marshmallow:Schema"
    schema_writer_factory = SchemaWriter

    def __init__(self, accessor, *, schema_class_path=None, schema_writer_factory=None):
        self.accessor = accessor
        self.schema_class_path = schema_class_path or self.__class__.schema_class_path
        self.schema_writer_factory = (
            schema_writer_factory or self.__class__.schema_writer_factory
        )
        self.schema_class = self.schema_class_path.rsplit(":", 1)[-1]

        self.files: t.Dict[str, Module] = {}

    @property
    def resolver(self) -> Resolver:
        return self.accessor.resolver

    def write_header(self, c: Context, *, comment: t.Optional[str] = None) -> None:
        if comment is None:
            comment = """\
# this is auto-generated by swagger-marshmallow-codegen
"""
        if not comment:
            return

        for line in comment.splitlines():
            c.im.stmt(line)

    def write_import_(self, c: Context) -> None:
        c.from_(*self.schema_class_path.rsplit(":", 1))
        c.from_("marshmallow", "fields")
        if self.accessor.config.get('emit_model', False):
            c.from_("marshmallow", "EXCLUDE")
            c.from_("marshmallow", "post_load")

    def write_model(self, context_factory: ContextFactory) -> None:
        if not self.accessor.config.get('emit_model', False):
            return

        def default_operations():
            sc.m.stmt("_url = ''")
            sc.m.stmt("_method = ''")

            with sc.m.def_('get_url', 'self'):
                sc.m.stmt('return self._url')

            with sc.m.def_('get_body', 'self'):
                sc.m.stmt('return {}')

        def init():
            with sc.m.def_('__init__', 'self', '*args', '**kwargs'):
                sc.m.stmt('model_kwargs = self._strip(kwargs)')
                sc.m.stmt('schema_kwargs = {k:v for k, v in kwargs.items() if k not in model_kwargs}')
                sc.m.stmt('super().__init__(*args, **schema_kwargs)')
                with sc.m.for_('key, arg in model_kwargs.items()'):
                    sc.m.stmt('setattr(self, key, arg)')

        def post_load():
            sc.m.stmt('@post_load')
            with sc.m.def_('__load', 'self', 'data', '**kwargs'):
                sc.m.stmt('return type(self)(**data)')

        def strip():
            with sc.m.def_('_strip', 'self', 'obj'):
                with sc.m.if_("hasattr(obj, '__dict__')"):
                    sc.m.stmt('obj = obj.__dict__')
                with sc.m.elif_('not isinstance(obj, dict)'):
                    sc.m.stmt('return obj')
                sc.m.stmt('return {k:v for k, v in obj.items() if k in self._declared_fields and v is not None}')

        def repr():
            with sc.m.def_('__repr__', 'self'):
                sc.m.stmt('args = \', \'.join("{!s}={!r}".format(key,val) for (key,val) in self.__strip(self).items())')
                sc.m.stmt('return "{}({})".format(self.__class__.__name__, args)')

        def schema_override_methods():
            with sc.m.def_('validate', 'self', 'obj', '*args', '**kwargs'):
                sc.m.stmt('return Schema.validate(self, self._strip(obj), *args, **kwargs)')

            with sc.m.def_('dump', 'self', 'obj', '*args', '**kwargs'):
                sc.m.stmt('return Schema.dump(self, self._strip(obj), *args, **kwargs)')

            with sc.m.def_('load', 'self', 'obj', '*args', '**kwargs'):
                sc.m.stmt('return Schema.load(self, self._strip(obj), *args, **kwargs)')

        sc = context_factory('', part=self.__class__.__name__)
        with sc.m.class_('Model', 'Schema'):
            default_operations()
            init()
            strip()
            repr()
            schema_override_methods()
            post_load()

        with sc.m.class_('Query', 'Schema'):
            with sc.m.def_('get_query', 'self'):
                sc.m.stmt('query_class = next(filter(lambda c: c.__base__ == __class__, type(self).__bases__))()')
                sc.m.stmt('query_params = query_class.load(self.__dict__, unknown=EXCLUDE)')
                sc.m.stmt("args = '&'.join(['{k}={v}'.format(k=k, v=v) for k, v in query_class.dump(query_params).items()])")
                sc.m.stmt("return '?{args}'.format(args=args) if args else ''")

        with sc.m.class_('Path', 'Schema'):
            with sc.m.def_('get_url', 'self'):
                sc.m.stmt('path_class = next(filter(lambda c: c.__base__ == __class__, type(self).__bases__))()')
                sc.m.stmt('url_params = path_class.load(self.__dict__, unknown=EXCLUDE)')
                sc.m.stmt('url = super().get_url().format(**path_class.dump(url_params))')
                sc.m.stmt("query = self.get_query() if hasattr(self, 'get_query') else ''")
                sc.m.stmt('return url + query')

        with sc.m.class_('Body', 'Schema'):
            with sc.m.def_('get_body', 'self'):
                sc.m.stmt('body_class = next(filter(lambda c: c.__base__ == __class__, type(self).__bases__))()')
                sc.m.stmt('body = body_class.load(self.__dict__, unknown=EXCLUDE)')
                sc.m.stmt('return body_class.dump(body)')

    def write_body(self, d: InputData, *, context_factory: ContextFactory) -> None:
        # TODO: get from context
        sw = self.schema_writer_factory(self.accessor, self.schema_class)

        config = self.accessor.config
        if config.get("emit_schema", False):
            DefinitionsSchemaWriter(self.accessor, sw).write(
                d, context_factory=context_factory
            )
        if config.get("emit_input", False):
            PathsSchemaWriter(self.accessor, sw).write(
                d, context_factory=context_factory
            )
        if config.get("emit_output", False):
            ResponsesSchemaWriter(self.accessor, sw).write(
                d, context_factory=context_factory
            )

    def setup_context(self, ctx: Context) -> None:
        self.write_header(ctx, comment=self.accessor.config.get("header_comment"))
        self.write_import_(ctx)
        ctx.m.sep()

    def codegen(self, d: InputData, context_factory) -> OutputData:
        self.write_model(context_factory=context_factory)
        self.write_body(d, context_factory=context_factory)
        return context_factory


def lazy_json_dump(s):
    import json

    return LazyCallString(json.dumps, s)

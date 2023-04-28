from __future__ import annotations
import typing as t
import keyword
import logging
import builtins
import re
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
        self.pending = {}
        self.pending_args = defaultdict(list)
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
        schema_name = None,
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
            raw_type = self.accessor.resolver.resolve_caller_name(c, name, field, True)
            raw_type = field_class_name or str(schema_name) if raw_type is object else raw_type
            inner_caller_name, types = self._get_caller(
                c,
                d,
                name,
                caller_name,
                field_class_name,
                field,
                opts={},
                schema_name=schema_name,
                many=self.resolver.has_many(field),
            )
            types = [raw_type] if not types else types
            opts.pop("many", None)
            opts = {k: repr(v) for k, v in opts.items()}
            return LazyFormat(
                "fields.List({})",
                LazyArgumentsAndKeywords(
                    [
                        inner_caller_name
                    ],
                    opts,
                ),
            ), types

        if field is None:
            opts = {k: repr(v) for k, v in opts.items()}
            if caller_name == "fields.Nested":
                return LazyFormat(
                    "fields.Nested({})",
                    LazyArgumentsAndKeywords([c.use_relative(field_class_name, separated=True)], opts,),
                ), [field_class_name]
            else:
                return LazyFormat("{}({})", caller_name, LazyKeywords(opts)), []
        elif self.resolver.has_nested(d, field) and field_class_name:
            logger.debug("      nested: %s, %s", caller_name, field_class_name)
            self.accessor.update_option_on_property(c, field, opts)
            opts = {k: repr(v) for k, v in opts.items()}
            return LazyFormat(
                "fields.Nested({})",
                LazyArgumentsAndKeywords([c.use_relative(field_class_name, separated=True)], opts,),
            ), [field_class_name]
        elif caller_name == "fields.Dict":
            self.accessor.update_option_on_property(c, field, opts)
            try:
                field = field["additionalProperties"]
            except KeyError:
                caller_name = self.accessor.resolver.resolve_caller_name(c, name, field)
                raw_type = self.accessor.resolver.resolve_caller_name(c, name, field, True)
                raw_type = field_class_name or str(schema_name) if raw_type is object else raw_type
                return LazyFormat(
                    "fields.Dict(keys=fields.String(), values={})",
                    caller_name,
                    LazyKeywords(opts),
                ), [raw_type]

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
            raw_type = self.accessor.resolver.resolve_caller_name(c, name, field, True)
            raw_type = field_class_name or str(schema_name) if raw_type is object else raw_type
            opts = {k: repr(v) for k, v in opts.items()}
            inner_caller_name, types = self._get_caller(
                c,
                d,
                name,
                caller_name,
                field_class_name,
                self.accessor.additional_properties(field) or field,
                opts={},
                schema_name=schema_name,
                many=self.resolver.has_many(field),
            )
            return LazyFormat(
                "fields.Dict(keys=fields.String(), values={})",
                LazyArgumentsAndKeywords(
                    [
                        inner_caller_name
                    ],
                    opts,
                ),
            ), [raw_type, *types]
        elif caller_name == "fields.Nested" and self.resolver.has_schema(d, field):
            self.accessor.update_option_on_property(c, field, opts)
            opts = {k: repr(v) for k, v in opts.items()}
            new_ref_name = str(LazyFormat("{}{}", schema_name, titleize(name)))
            self.pending[new_ref_name] = field
            return LazyFormat("{}({})", caller_name, c.use_relative(new_ref_name, separated=True)), [new_ref_name]
        else:
            self.accessor.update_option_on_property(c, field, opts)
            opts = {k: repr(v) for k, v in opts.items()}
            if caller_name == "fields.Nested":
                caller_name = "fields.Field"
            return LazyFormat("{}({})", caller_name, LazyKeywords(opts)), []

    def resolve_types(self, c, type_list):
        if not type_list:
            return ''
        elif type_list[0] == dict:
            return '{}[str, {}]'.format(type_list[0].__name__, self.resolve_types(c, type_list[1:]))
        elif type_list[0] == list:
            return '{}[{}]'.format(type_list[0].__name__, self.resolve_types(c, type_list[1:]))
        elif isinstance(type_list[0], str):
            return type_list[0]
        else:
            return type_list[0].__name__


    def write_field_one(
        self, c, d, schema_name, definition, name, field, opts, original_schema_name, *, many: bool = False
    ):
        field_class_name = None
        if self.resolver.has_ref(field):
            field_class_name, field = self.resolver.resolve_ref_definition(
                c, d, field, level=1
            )
            if self.resolver.has_many(field):
                return self.write_field_one(
                    c, d, field_class_name, definition, name, field, opts, original_schema_name=original_schema_name, many=True
                )

            # finding original definition
            if self.resolver.has_ref(field):
                ref_name, field = self.resolver.resolve_ref_definition(c, d, field)
                if self.resolver.has_many(field):
                    return self.write_field_one(
                        c, d, field_class_name, definition, name, field, opts, original_schema_name=original_schema_name, many=True
                    )
                if ref_name is None:
                    raise CodegenError("ref: %r is not found", field["$ref"])

        logger.debug("      field: %s", lazy_json_dump(field))
        caller_name = self.accessor.resolver.resolve_caller_name(c, name, field)
        raw_type = self.accessor.resolver.resolve_caller_name(c, name, field, True)
        raw_type = field_class_name or str(schema_name) if raw_type is object else raw_type
        if caller_name is None:
            logger.error("matched field class is not found. name=%r, schema=%r, field=%r",
                name,
                str(schema_name),
                field)
            return 

        normalized_name = self.resolver.resolve_normalized_name(name)
        if normalized_name != name:
            opts["data_key"] = name
        if keyword.iskeyword(normalized_name) or normalized_name in schema_params:
            opts["data_key"] = normalized_name
            normalized_name = normalized_name + "_"


        inner_name, types = self._get_caller(
            c, d, name, caller_name, field_class_name, field, opts=opts, schema_name=schema_name, many=many
        )
        caller_type = self.resolve_types(c, [raw_type, *types])
        if opts.get('allow_none'):
            caller_type = '{}|None'.format(caller_type)
        caller_type = caller_type if caller_type in map(str, dir(builtins)) else "'{}'".format(caller_type)
        logger.info("  write field: name=%s, field=%s, type=%s", normalized_name, caller_name, caller_type)
        c.m.stmt(
            "{}{} = {}",
            normalized_name,
            ': {}'.format(caller_type) if self.accessor.config.get('emit_model', False) else '',
            inner_name,
        )
        key = original_schema_name if str(schema_name).startswith(str(original_schema_name)) else schema_name
        if normalized_name not in self.pending_args[key]:
            if str(normalized_name) == 'excludedDbList':
                logger.error(str([normalized_name, str(key), str(raw_type), name]))
            self.pending_args[key].append(normalized_name)

        return normalized_name

    def write_primitive_schema(self, c, d, clsname, definition, many=False):
        c.im.from_(self.extra_schema_module, "PrimitiveValueSchema")
        with c.m.class_(clsname, "PrimitiveValueSchema"):
            with c.m.class_("schema_class", self.schema_class):
                if many or self.resolver.has_many(definition):
                    definition["type"] = "array"
                    self.write_field_one(
                        c, d, clsname, {}, "value", definition, {}, original_schema_name=clsname, many=True
                    )
                else:
                    self.write_field_one(c, d, clsname, {}, "value", definition, {}, original_schema_name=clsname)

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
                    base_classes.append(ref_name)
            else:
                if not self.resolver.has_schema(d, ref_definition):
                    self.write_primitive_schema(
                        c, d, clsname, ref_definition, many=many
                    )
                    return field_names
                field_names.extend(self.write_schema(c, d, ref_name, ref_definition))
                base_classes.append(ref_name)
            if 'Model' in base_classes:
                base_classes.append(base_classes.pop(base_classes.index('Model')))
            if 'Exception' in base_classes:
                base_classes.append(base_classes.pop(base_classes.index('Exception')))

        has_allof = self.resolver.has_allof(definition) or self.resolver.has_allof(self.accessor.properties(definition))
        if has_allof:
            definition = self.accessor.properties(definition) or definition
            ref_list, ref_definition = self.resolver.resolve_allof_definition(
                c, d, definition
            )
            definition = deepmerge(ref_definition, self.accessor.properties(definition) or definition)
            if ref_list and'Model' in base_classes:
                base_classes.remove('Model')
            for ref_name, ref_definition in ref_list:
                c.relative_import(ref_name)
                if ref_name is None:
                    raise CodegenError(
                        "$ref %r is not found", ref_definition
                    )  # xxx
                else:
                    logger.error('!!!' + str(clsname) + ' ' + ref_name + str(self.pending_args[ref_name]))
                    field_names.extend(self.pending_args[ref_name])
                    base_classes.append(ref_name)

        # supporting additional properties
        if (
            hasattr(definition.get("additionalProperties"), "keys")
            and base_classes[0] == self.schema_class
        ):
            c.from_(self.extra_schema_module, "AdditionalPropertiesSchema")
            base_classes[0] = "AdditionalPropertiesSchema"

        if "properties" not in definition and (
            isinstance(definition.get("type", "object"), str) and "object" != definition.get("type", "object") and "items" not in definition
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
                    base_classes.append(ref_name)

        with c.m.class_(clsname, bases=base_classes):
            need_pass_statement = True

            if description:
                c.m.stmt('"""')
                for line in (
                    description.rstrip("\n").split("\n")
                ):
                    c.m.stmt(line)
                c.m.stmt('"""')
                c.m.stmt("")
                need_pass_statement = False

            if meta_writer is not None:
                meta_writer(c.m)
                need_pass_statement = False

            if many or self.resolver.has_many(definition):
                with c.m.def_("__init__", "self", "*args", "**kwargs"):
                    c.m.stmt("kwargs['many'] = True")
                    c.m.stmt("super().__init__(*args, **kwargs)")

            opts = defaultdict(OrderedDict)
            self.accessor.update_options_pre_properties(definition, opts)

            properties = self.accessor.properties(definition)
            if not properties and definition and not self.resolver.has_ref(definition) \
                    and not self.accessor.additional_properties(definition):
                properties = definition
            if not has_allof and (properties or (many and not self.accessor.additional_properties(definition))):
                need_pass_statement = False
                for name, field in properties.items():
                    name = str(name)
                    field_name = self.write_field_one(
                        c,
                        d,
                        clsname,
                        definition,
                        name,
                        field,
                        opts[name],
                        original_schema_name=clsname,
                        many=self.resolver.has_many(field),
                    )
                    if field_name:
                        field_names.append(field_name)

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
                            original_schema_name=clsname,
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
                            original_schema_name=clsname,
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

            if (any(base in base_classes for base in ('Model', 'Method')) or (has_allof and any(base in base_classes for base in ('Base', 'Path', 'Query')))) and field_names:
                need_pass_statement = False
                kwargs = ['{kwarg}=None'.format(kwarg=kwarg) for kwarg in field_names]
                with c.m.def_('__init__', 'self', '*args', *kwargs, '**kwargs'):
                    c.m.stmt('kwargs.update(self._strip_locals(locals()))')
                    c.m.stmt('super().__init__(*args, **kwargs)')

            if need_pass_statement:
                c.m.stmt("pass")

        for ref_name, field in self.pending.copy().items():
            if has_allof and 'Model' in base_classes:
                base_classes.remove('Model')
            field_names.extend(self.write_schema(c, d, ref_name, field, base_classes=base_classes))
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
            bases = ['Model'] if self.accessor.config.get('emit_model', False) else []
            self.schema_writer.write_schema(c, d, clsname, definition, force=True, base_classes=bases)


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
                path_name = str(LazyFormat("{}{}", lazy_clsname, titleize(method)))
                if definition.get('operationId', None):
                    path_name = definition['operationId']
                logger.info("write method: %s", path_name)
                sc.store_path(path_name, 'url', path)
                sc.store_path(path_name, 'operation', method)

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
                paths = ['Path'], filter(lambda section: section[0] == 'path', info)
                queries = ['Query'], filter(lambda section: section[0] == 'query', info)
                json_bodies = ['Body'], sorted(body_info.info.items())

                bodies = filter(lambda section: section[0] == 'body', info)
                for section, properties in bodies:
                    name = LazyFormat("{}{}", path_name, titleize(section))
                    sc.store_path(path_name, 'method', str(name))
                    properties["description"] = description
                    self.schema_writer.write_schema(
                        ssc, d, name, properties, force=True
                    )

                for bases, section_type in [json_bodies, queries, paths]:
                    for section, properties in section_type:
                        name = LazyFormat("{}{}", path_name, titleize(section))
                        sc.store_path(path_name, 'method', str(name))
                        for key, props_data in properties.items():
                            if key not in ("$ref", "allOf") and props_data.get("schema", {}).get('type', None):
                                props_data['type'] = props_data.pop('schema')['type']
                        data = {
                            "properties": properties,
                            "required": path_info.required[section],
                            "description": description,
                        }
                        if self.resolver.has_ref(properties):
                            data = properties
                        bases = bases if self.accessor.config.get('emit_model', False) else []
                        parameters = self.schema_writer.write_schema(
                            ssc, d, name, data, base_classes=bases
                        )
                        sc.store_path(path_name, section, parameters)


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
            if not parameters or not parameters.get('content', {}).get('application/json', {}).get('schema', {}):
                continue
            schema = parameters['content']['application/json']['schema']
            properties = self.resolve_properties(schema)
            if 'oneOf' in properties:
                continue
            if 'type' in properties and isinstance(properties['type'], str) and properties['type'] not in ('object', 'array'):
                continue
            info['body'] = properties
            required['body'] = schema.get('required', [])
        return PathInfo(info=info, required=required)

    def resolve_properties(self, properties):
        if self.accessor.additional_properties(properties):
            return self.resolve_properties(self.accessor.additional_properties(properties))
        elif self.accessor.properties(properties):
            return self.resolve_properties(self.accessor.properties(properties))
        elif self.resolver.has_many(properties):
            return self.resolve_properties(properties['items'])
        return properties


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
            if self.OVERRIDE_NAME_MARKER in methods:
                lazy_clsname.pop()
                lazy_clsname.append(methods[self.OVERRIDE_NAME_MARKER])
            for method, definition in self.accessor.methods(methods):
                path_name = str(LazyFormat("{}{}", lazy_clsname, titleize(method)))
                if definition.get('operationId', None):
                    path_name = definition['operationId']
                had_response = False
                for status, definition in self.accessor.responses(definition):
                    name = LazyFormat("{}{}", path_name, str(status))
                    logger.info("write response: %s", name)
                    description = definition.get('description', None)
                    body_info = self.build_body_info(
                        sc,
                        d,
                        definition
                    )
                    bases, json_bodies = ['Model'], sorted(body_info.info.items())
                    if had_response:
                        bases.append('Exception')
                    if "schema" in definition:
                        with sc.m.class_(name):
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
                    elif json_bodies:
                        for section, properties in json_bodies:
                            def meta(m):
                                if description:
                                    m.stmt('"""')
                                    for line in (
                                        description.rstrip("\n").split("\n")
                                    ):
                                        m.stmt(line)
                                    m.stmt('"""')
                                    m.stmt("")

                            data = properties.copy()
                            if body_info.required[section]:
                                data['required'] =  body_info.required[section]
                            bases = bases if self.accessor.config.get('emit_model', False) else []
                            self.schema_writer.write_schema(
                                sc, d, name, data,
                                meta_writer=meta,
                                base_classes=bases
                            )
                        if not had_response and not re.match(r'.*[3-5][0-9][0-9]', str(name)):
                            had_response = True
                            sc.store_path(path_name, 'response', str(name))
                        else:
                            sc.store_path(path_name, 'exceptions', str(name))
                        
    def build_body_info(
        self,
        c: Context,
        fulldata: t.Dict[str, t.Any],
        *paramaters_set: t.List[t.Dict[str, t.Any]]
    ) -> PathInfo:
        info = defaultdict(OrderedDict)
        required = defaultdict(list)
        for parameters in paramaters_set:
            if not parameters or not parameters.get('content', {}).get('application/json', {}).get('schema', {}):
                continue
            schema = parameters['content']['application/json']['schema']
            properties = self.resolve_properties(schema)
            if 'oneOf' in properties:
                continue
            if 'type' in properties and isinstance(properties['type'], str) and properties['type'] not in ('object', 'array'):
                continue
            info['body'] = properties
            required['body'] = schema.get('required', [])
        return PathInfo(info=info, required=required)

    def resolve_properties(self, properties):
        if self.accessor.additional_properties(properties):
            return self.resolve_properties(self.accessor.additional_properties(properties))
        elif self.accessor.properties(properties):
            return self.resolve_properties(self.accessor.properties(properties))
        elif self.resolver.has_many(properties):
            return self.resolve_properties(properties['items'])
        return properties


class MethodWriter:
    OVERRIDE_NAME_MARKER = NAME_MARKER

    def __init__(self, accessor, schema_writer):
        self.accessor = accessor
        self.schema_writer = schema_writer

    @property
    def resolver(self) -> Resolver:
        return self.accessor.resolver

    def write_request(self, sc, info):
        if info.get('response', []):
            sc.m.stmt("_response = {}()".format(info['response'][0]))
        if info.get('exceptions', []):
            exceptions = '(), '.join(info['exceptions']) + '()'
            sc.m.stmt("_exceptions = [{}]".format(exceptions))
        if info.get('response', []):
            with sc.m.def_('request', 'self', 'base_url', 'session'):
                sc.m.stmt('super().request(base_url, session)')
                sc.m.stmt('return self._response')

    def write(self, d: InputData, *, context_factory: ContextFactory) -> None:
        part = self.__class__.__name__
        sc = context_factory('', part=part)
        for path, info in sc.collected_paths.items():
            method_kwargs = []
            for key in ('body', 'path', 'query'):
                method_kwargs.extend(info[key])
            bases = info['method'] + ['Method']

            with sc.m.class_(path, bases=bases):
                sc.m.stmt("_method = '{}'".format(info['operation'][0]))
                sc.m.stmt("_url = '{}'".format(info['url'][0]))
                self.write_request(sc, info)
                kwargs = ['{kwarg}=None'.format(kwarg=kwarg) for kwarg in method_kwargs]
                if kwargs:
                    with sc.m.def_('__init__', 'self', '*args', *kwargs, '**kwargs'):
                        sc.m.stmt('kwargs.update(self._strip_locals(locals()))')
                        sc.m.stmt('super().__init__(*args, **kwargs)')


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
# pylint: disable=no-self-use, inconsistent-return-statements, too-many-locals, too-many-ancestors
"""
        if not comment:
            return

        for line in comment.splitlines():
            c.im.stmt(line)

    def write_import_(self, c: Context) -> None:
        c.from_(*self.schema_class_path.rsplit(":", 1))
        c.from_('typing', 'TypeVar')
        c.from_("marshmallow", "fields")
        if self.accessor.config.get('emit_model', False):
            c.from_("marshmallow", "EXCLUDE")
            c.from_("marshmallow", "INCLUDE")
            c.from_("marshmallow", "RAISE")
            c.from_("marshmallow", "post_load")
            c.from_('requests.exceptions', 'HTTPError')
            c.from_('marshmallow.validate', 'ValidationError')
            c.from_('datetime', 'datetime')
            c.from_('datetime', 'date')
            c.from_('datetime', 'time')

    def write_model(self, context_factory: ContextFactory) -> None:
        if not self.accessor.config.get('emit_model', False):
            return

        def default_operations():
            sc.m.stmt("_url = ''")
            sc.m.stmt("_method = ''")
            sc.m.stmt('_response = None')
            sc.m.stmt('_exceptions = []')

            with sc.m.def_('body', 'self'):
                with sc.m.try_():
                    with sc.m.if_('self._list is not None'):
                        sc.m.return_('[body.get_body() for body in self._list]')
                    sc.m.stmt('return self.get_body()')
                with sc.m.except_('AttributeError'):
                    sc.m.stmt('return {}')

            with sc.m.def_('url', 'self'):
                with sc.m.try_():
                    sc.m.stmt('url = self.get_url()')
                with sc.m.except_('AttributeError'):
                    sc.m.stmt('url = self._url')
                with sc.m.try_():
                    sc.m.stmt('return url + self.get_query()')
                with sc.m.except_('AttributeError'):
                    sc.m.stmt('return url')

            with sc.m.def_('request', 'self', 'base_url', 'session'):
                sc.m.stmt('self.load(self)')
                with sc.m.with_('session() as sess'):
                    sc.m.stmt('kwargs = {}')
                    sc.m.stmt('body = self.body()')
                    with sc.m.if_('body'):
                        sc.m.stmt("kwargs['json'] = body")
                    with sc.m.try_():
                        sc.m.stmt('response = sess.request(self._method, base_url + self.url(), **kwargs)')
                        sc.m.stmt('response.raise_for_status()')
                    with sc.m.except_('HTTPError as exc'):
                        with sc.m.for_('exception in self._exceptions'):
                            with sc.m.try_():
                                sc.m.stmt('data = response.json()')
                            with sc.m.except_('Exception'):
                                sc.m.stmt('raise exc')
                            with sc.m.try_():
                                sc.m.stmt('raise exception.load(exc.response.json())')
                            with sc.m.except_('(ValidationError, AttributeError)'):
                                sc.m.stmt('pass')
                        sc.m.stmt('raise exc')
                    with sc.m.if_('response.status_code == 204'):
                        sc.m.stmt('return')
                    with sc.m.try_():
                        sc.m.stmt('data = response.json()')
                    with sc.m.except_('Exception'):
                        sc.m.stmt('data = response.text')
                    with sc.m.if_('isinstance(self._response, Schema)'):
                        sc.m.stmt('self._response = self._response.load(data)')
                    sc.m.stmt('return data')

        def meta_unknown(operation):
            with sc.m.class_('Meta', 'Schema'):
                sc.m.stmt('unknown = {}'.format(operation))

        def init():
            with sc.m.def_('__init__', 'self', '*args', '**kwargs'):
                sc.m.stmt('model_kwargs = self._strip(kwargs)')
                sc.m.stmt('schema_kwargs = {k: v for k, v in kwargs.items() if k not in model_kwargs}')
                sc.m.stmt('super().__init__(*args, **schema_kwargs)')
                with sc.m.for_('key, arg in model_kwargs.items()'):
                    sc.m.stmt('setattr(self, key, arg)')

        def load_list():
            with sc.m.def_('load_list', 'self', '_list'):
                sc.m.stmt('self._list = [self.load(item) for item in _list]')
                sc.m.return_('self')

        def post_load():
            sc.m.stmt('@post_load')
            with sc.m.def_('__load', 'self', 'data', '**kwargs'):
                sc.m.stmt('return type(self)(**data)')

        def strip():
            with sc.m.def_('_strip', 'self', 'obj'):
                with sc.m.if_('isinstance(obj, (list, tuple))'):
                    sc.m.stmt('return [self._strip(item) for item in obj]')
                with sc.m.if_("hasattr(obj, '__dict__')"):
                    sc.m.stmt('obj = obj.__dict__')
                with sc.m.if_('not isinstance(obj, dict)'):
                    sc.m.stmt('return obj')
                sc.m.stmt('return {k:v for k, v in obj.items() if k not in vars(Schema()) and k != \'_list\'}')

            with sc.m.def_('_strip_locals', 'self', 'locals'):
                sc.m.stmt('return {k: v for k, v in locals.items() if k not in [\'self\', \'__class__\', \'args\', \'kwargs\'] and v is not None}')

        def _has_processors():
            with sc.m.def_('_has_processors', 'self', 'tag'):
                sc.m.stmt('return bool(self._hooks[(tag, True)] or self._hooks[(tag, False)])')

        def get_attr():
            with sc.m.def_('__getattr__', 'self', 'key', 'default=None'):
                with sc.m.try_():
                    sc.m.stmt('return super().getattr(self, key, default)')
                with sc.m.except_('AttributeError'):
                    with sc.m.if_('key in self._declared_fields'):
                        sc.m.stmt('return default if default is not None else {}')
                    sc.m.stmt('raise')
        def repr():
            with sc.m.def_('__repr__', 'self'):
                sc.m.stmt('args = \', \'.join("{!s}={!r}".format(key, val) for (key, val) in self._strip(self).items())')
                sc.m.stmt('return "{}({})".format(self.__class__.__name__, args)')

            with sc.m.def_('__str__', 'self'):
                sc.m.stmt('return repr(self)')

            with sc.m.def_('toJson', 'self'):
                sc.m.stmt('return self.dump(self)')

        def eq():
            with sc.m.def_('__eq__', 'self', 'other'):
                sc.m.stmt('return self.toJson() == other')

        def schema_override_methods():
            with sc.m.def_('validate', 'self', 'obj', '*args', '**kwargs'):
                sc.m.stmt('data = self._strip(obj)')
                with sc.m.if_('isinstance(data, list)'):
                    sc.m.stmt('return [Schema.validate(self, d, *args, **kwargs) for d in data]')
                sc.m.stmt('return Schema.validate(self, data, *args, **kwargs)')

            with sc.m.def_('dump', 'self', 'obj', '*args', '**kwargs'):
                sc.m.stmt('data = self._strip(obj)')
                with sc.m.if_('isinstance(data, list)'):
                    sc.m.stmt('return [Schema.dump(self, d, *args, **kwargs) for d in data]')
                sc.m.stmt('return Schema.dump(self, data, *args, **kwargs)')

            with sc.m.def_('load', 'self: T', 'obj', '*args', '**kwargs', return_type='T'):
                sc.m.stmt('data = self._strip(obj)')
                with sc.m.if_('isinstance(data, list)'):
                    sc.m.stmt('return [Schema.load(self, d, *args, **kwargs) for d in data]')
                sc.m.stmt('return Schema.load(self, data, *args, **kwargs)')

        sc = context_factory('', part=self.__class__.__name__)
        sc.m.stmt("T = TypeVar('T')")
        with sc.m.class_('Model', 'Schema'):
            sc.m.stmt('_list = None')
            meta_unknown('INCLUDE')
            init()
            strip()
            get_attr()
            _has_processors()
            repr()
            eq()
            schema_override_methods()
            load_list()
            post_load()

        with sc.m.class_('Method', 'Model'):
            meta_unknown('RAISE')
            default_operations()

        with sc.m.class_('Query', 'Schema'):
            with sc.m.def_('get_query', 'self'):
                sc.m.stmt('query_class = next(filter(lambda c: c.__base__ == __class__, type(self).__bases__))()')
                sc.m.stmt('query_params = query_class.load(self.__dict__, unknown=EXCLUDE)')
                sc.m.stmt("args = '&'.join(['{k}={v}'.format(k=k, v=v) for k, v in query_class.dump(query_params).items()])")
                sc.m.stmt("return '?{args}'.format(args=args) if args else ''")

        with sc.m.class_('Path', 'Schema'):
            sc.m.stmt("_url = ''")
            with sc.m.def_('get_url', 'self'):
                sc.m.stmt('path_class = next(filter(lambda c: c.__base__ == __class__, type(self).__bases__))()')
                sc.m.stmt('url_params = path_class.load(self.__dict__, unknown=EXCLUDE)')
                sc.m.stmt('return self._url.format(**path_class.dump(url_params))')

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

        if config.get('emit_model', False):
            MethodWriter(self.accessor, sw).write(
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

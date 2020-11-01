from __future__ import annotations
import typing_extensions as tx


class ConfigDict(tx.TypedDict):
    schema: bool
    input: bool
    output: bool

    emit_schema_even_primitive_type: bool
    skip_header_comment: bool
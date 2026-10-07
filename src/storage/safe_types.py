from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.types import String, TypeDecorator

if TYPE_CHECKING:
    from sqlalchemy.engine import Dialect

_SURROGATE_RANGE = range(0xD800, 0xDFFF + 1)
_MARKER_PATTERN = re.compile(r'\\\\|\\u([0-9A-Fa-f]{4})')
_STRIP_PATTERN = re.compile(r'[\0\ud800-\udfff]')


def _escape_string(value: str) -> str:
    escaped = value.replace('\\', '\\\\')
    escaped = escaped.replace('\0', '\\u0000')
    return re.sub(r'[\ud800-\udfff]', lambda match: f'\\u{ord(match.group()):04x}', escaped)


def _unescape_string(value: str) -> str:
    def replace(match: re.Match) -> str:
        if match.group(1) is None:
            return '\\'
        code = int(match.group(1), 16)
        if code == 0 or code in _SURROGATE_RANGE:
            return chr(code)
        return match.group(0)

    return _MARKER_PATTERN.sub(replace, value)


def _escape_json(value: Any) -> Any:  # noqa: ANN401
    if isinstance(value, dict):
        return {_escape_string(k) if isinstance(k, str) else k: _escape_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_escape_json(v) for v in value]
    if isinstance(value, str):
        return _escape_string(value)
    return value


def _unescape_json(value: Any) -> Any:  # noqa: ANN401
    if isinstance(value, dict):
        return {_unescape_string(k) if isinstance(k, str) else k: _unescape_json(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unescape_json(v) for v in value]
    if isinstance(value, str):
        return _unescape_string(value)
    return value


def _strip_unsafe_chars(value: Any) -> Any:  # noqa: ANN401
    if isinstance(value, dict):
        return {_strip_unsafe_chars(k) if isinstance(k, str) else k: _strip_unsafe_chars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_unsafe_chars(v) for v in value]
    if isinstance(value, str):
        return _STRIP_PATTERN.sub('', value)
    return value


class SafeString(TypeDecorator):
    """VARCHAR storing null bytes and lone surrogates in a reversible escaped form."""

    impl = String
    cache_ok = True

    def coerce_compared_value(self, op, value) -> Any:  # noqa: ANN001, ANN401
        return self.impl_instance.coerce_compared_value(op, value)

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:  # noqa: ARG002
        if value is None:
            return None
        return _escape_string(value)

    def process_result_value(self, value: str | None, dialect: Dialect) -> str | None:  # noqa: ARG002
        if value is None:
            return None
        return _unescape_string(value)


class SafeJSONB(TypeDecorator):
    """JSONB storing null bytes and lone surrogates in a reversible escaped form."""

    impl = JSONB
    cache_ok = True

    def coerce_compared_value(self, op, value) -> Any:  # noqa: ANN001, ANN401
        return self.impl_instance.coerce_compared_value(op, value)

    def process_bind_param(self, value: Any, dialect: Dialect) -> Any:  # noqa: ARG002, ANN401
        if value is None:
            return None
        return _escape_json(value)

    def process_result_value(self, value: Any, dialect: Dialect) -> Any:  # noqa: ARG002, ANN401
        if value is None:
            return None
        return _unescape_json(value)

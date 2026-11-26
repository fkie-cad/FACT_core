import pytest

from storage.safe_types import _escape_json, _escape_string, _strip_unsafe_chars, _unescape_json, _unescape_string


@pytest.mark.parametrize(
    ('value', 'expected_escaped'),
    [
        ('plain', 'plain'),
        ('a\0b', 'a\\u0000b'),
        ('\\u0000', '\\\\u0000'),
        ('\\u0041', '\\\\u0041'),
        ('\\\0', '\\\\\\u0000'),  # backslash + null byte -> doubled backslash + null-byte marker
        ('\udcc4\udcd6\udcdc', '\\udcc4\\udcd6\\udcdc'),
        ('a\0\\\0\udcc4\u0041\\\\', 'a\\u0000\\\\\\u0000\\udcc4A\\\\\\\\'),
        ('back\\slash\\u0000', 'back\\\\slash\\\\u0000'),
    ],
)
def test_escape_string_roundtrip(value, expected_escaped):
    escaped = _escape_string(value)
    assert escaped == expected_escaped
    assert _unescape_string(escaped) == value


@pytest.mark.parametrize(
    ('value', 'expected_unescaped'),
    [
        ('\\u0000', '\0'),
        ('\\udcc4', '\udcc4'),
        ('\\u0041', '\\u0041'),  # non-marker escape stays as-is
        ('\\\\', '\\'),
        ('a\\\\b', 'a\\b'),
    ],
)
def test_unescape_string(value, expected_unescaped):
    assert _unescape_string(value) == expected_unescaped


@pytest.mark.parametrize(
    'value',
    [
        {},
        {'a': 1, 'b': 'x\0y'},
        {'nested': {'k': 'v\udcc4'}, 'list': ['a\0', {'x': 'y'}]},
        {'\0key': 'val', 'key': ['\udcc4', 1, True, None]},
        [1, 'a\0', {'k': '\udcc4'}],
        'string\0with\udcc4surrogate',
        None,
    ],
)
def test_escape_json_roundtrip(value):
    escaped = _escape_json(value)
    if isinstance(value, (dict, list)):
        assert _unescape_json(escaped) == value
    elif isinstance(value, str):
        assert _unescape_string(escaped) == value
    else:
        assert escaped == value


def test_escape_json_preserves_other_types():
    value = {'int': 1, 'float': 1.5, 'bool': True, 'none': None, 'bytes': b'data'}
    escaped = _escape_json(value)
    assert escaped['int'] == 1
    assert escaped['float'] == 1.5
    assert escaped['bool'] is True
    assert escaped['none'] is None
    assert escaped['bytes'] == b'data'


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        ('plain', 'plain'),
        ('a\0b', 'ab'),
        ('\0', ''),
        ('\ud800\udfff', ''),
        ('a\0b\udcc4c', 'abc'),
        ('\u0041\0', 'A'),
        (None, None),
        (1, 1),
        (True, True),
        (b'data\0', b'data\0'),
    ],
)
def test_strip_unsafe_chars_scalar(value, expected):
    assert _strip_unsafe_chars(value) == expected


def test_strip_unsafe_chars_dict():
    value = {'key\0name': 'val\0ue', 'nested': {'k': 'v\udcc4'}, 'ok': 'fine'}
    assert _strip_unsafe_chars(value) == {'keyname': 'value', 'nested': {'k': 'v'}, 'ok': 'fine'}


def test_strip_unsafe_chars_list():
    value = [{'k': '\ud800'}, 'a\0', 'plain']
    assert _strip_unsafe_chars(value) == [{'k': ''}, 'a', 'plain']


def test_strip_unsafe_chars_after_unescape():
    escaped = _escape_json({'key': 'a\0b\udcc4c'})
    assert _strip_unsafe_chars(_unescape_json(escaped)) == {'key': 'abc'}

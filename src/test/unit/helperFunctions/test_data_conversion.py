from datetime import datetime

import pytest

from helperFunctions.data_conversion import (
    convert_compare_id_to_list,
    convert_str_to_bool,
    convert_time_to_str,
    get_value_of_first_key,
    make_bytes,
    make_unicode_string,
    none_to_none,
    normalize_compare_id
)


@pytest.mark.parametrize(
    'input_data', [
        'test string',
        b'test string',
        [116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103],
    ]
)
def test_make_bytes(input_data):
    result = make_bytes(input_data)
    assert isinstance(result, bytes)
    assert result == b'test string'


@pytest.mark.parametrize(
    'input_data, expected',
    [
        ('test string', 'test string'), (b'test string', 'test string'), (b'\xc3\xbc test string', 'ü test string'),
        (b'\xf5 test string', '� test string'), (['test string'], '[\'test string\']')
    ]
)
def test_make_unicode_string(input_data, expected):
    result = make_unicode_string(input_data)
    assert isinstance(result, str)
    assert result == expected


def test_normalize_compare_id():
    ids_a = 'a;b'
    ids_b = 'b;a'
    assert normalize_compare_id(ids_a) == 'a;b', 'compare id not correct'
    assert normalize_compare_id(ids_a) == normalize_compare_id(ids_b), 'compare ids not the same'


@pytest.mark.parametrize('input_data, expected', [
    ('a', ['a']),
    ('a;b;c', ['a', 'b', 'c']),
])
def test_convert_compare_id_to_list(input_data, expected):
    assert convert_compare_id_to_list(input_data) == expected


@pytest.mark.parametrize('input_data, expected', [({'b': 'b', 'c': 'c', 'a': 'a'}, 'a'), ({}, None)])
def test_get_value_of_first_key(input_data, expected):
    assert get_value_of_first_key(input_data) == expected


@pytest.mark.parametrize('input_data, expected', [(None, None), ('None', None), ('foo', 'foo')])
def test_none_to_none(input_data, expected):
    assert none_to_none(input_data) == expected


@pytest.mark.parametrize(
    'input_data, expected', [(datetime(2000, 2, 29), '2000-02-29'), ('1999-01-01', '1999-01-01'), (None, '1970-01-01')]
)
def test_convert_time_to_str(input_data, expected):
    assert convert_time_to_str(input_data) == expected


@pytest.mark.parametrize(
    'input_str, expected_output',
    [
        ('yes', True),
        ('y', True),
        ('1', True),
        ('True', True),
        ('t', True),
        ('No', False),
        ('N', False),
        ('0', False),
        ('false', False),
        ('F', False),
    ]
)
def test_convert_str_to_bool(input_str, expected_output):
    assert convert_str_to_bool(input_str) == expected_output


def test_str_to_bool_error():
    with pytest.raises(ValueError):
        convert_str_to_bool('foo')

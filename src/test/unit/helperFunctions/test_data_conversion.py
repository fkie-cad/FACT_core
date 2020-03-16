from datetime import datetime

import pytest

from helperFunctions.dataConversion import (
    _fill_in_time_gaps, build_time_dict, convert_compare_id_to_list, convert_time_to_str, get_value_of_first_key,
    list_of_sets_to_list_of_lists, make_bytes, make_list_from_dict, make_unicode_string, none_to_none,
    normalize_compare_id, remove_subsets_from_list_of_sets
)


@pytest.mark.parametrize('input_data', [
    ('test string'),
    (b'test string'),
    ([116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103])
])
def test_make_bytes(input_data):
    result = make_bytes(input_data)
    assert isinstance(result, bytes)
    assert result == b'test string'


@pytest.mark.parametrize('input_data, expected', [
    ('test string', 'test string'),
    (b'test string', 'test string'),
    (b'\xc3\xbc test string', 'ü test string'),
    (b'\xf5 test string', '� test string'),
    (['test string'], '[\'test string\']')
])
def test_make_unicode_string(input_data, expected):
    result = make_unicode_string(input_data)
    assert isinstance(result, str)
    assert result == expected


def test_make_list_from_dict():
    test_dict = {'a': 'abc', 'b': 'bcd'}
    result_list = make_list_from_dict(test_dict)
    assert isinstance(result_list, list), 'type is not list'
    result_list.sort()
    assert result_list == ['abc', 'bcd'], 'resulting list not correct'


def test_list_of_sets_to_list_of_lists():
    input_sets = [{'a', 'b'}, {'b', 'c'}]
    result = list_of_sets_to_list_of_lists(input_sets)
    assert isinstance(result, list), 'result is not a list'
    for item in result:
        assert isinstance(item, list), '{} is not a list'.format(item)
    assert ['a', 'b'] in result, 'first list not found'
    assert list_of_sets_to_list_of_lists(None) == []


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


@pytest.mark.parametrize('input_data, expected', [
    ({'b': 'b', 'c': 'c', 'a': 'a'}, 'a'),
    ({}, None)
])
def test_get_value_of_first_key(input_data, expected):
    assert get_value_of_first_key(input_data) == expected


@pytest.mark.parametrize('input_list, expected_output', [
    ([], []),
    ([{1}, {2}, {3}], [{1}, {2}, {3}]),
    ([{1, 2}, {1}, {2}], [{1, 2}]),
    ([{1, 2}, {1}, {1, 2, 3}, {2, 1}, {1, 2, 4}, {3, 2, 1}, {1, 2}], [{1, 2, 3}, {1, 2, 4}]),
])
def test_remove_subsets_from_list_of_sets(input_list, expected_output):
    remove_subsets_from_list_of_sets(input_list)
    assert all(element in input_list for element in expected_output)
    assert len(input_list) == len(expected_output)


def test_build_time_dict():
    test_input = [{'_id': {'month': 12, 'year': 2016}, 'count': 10},
                  {'_id': {'month': 1, 'year': 2017}, 'count': 8}]
    expected_result = {2016: {12: 10}, 2017: {1: 8}}
    assert build_time_dict(test_input) == expected_result


@pytest.mark.parametrize('input_data, expected', [
    ({}, {}),
    ({2016: {11: 10}, 2017: {2: 8}}, {2016: {11: 10, 12: 0}, 2017: {1: 0, 2: 8}}),
    ({2000: {12: 1}, 2002: {1: 1}}, {2000: {12: 1}, 2001: {1: 0, 2: 0, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0}, 2002: {1: 1}})
])
def test_fill_in_time_gaps(input_data, expected):
    _fill_in_time_gaps(input_data)
    assert input_data == expected


@pytest.mark.parametrize('input_data, expected', [
    (None, None),
    ('None', None),
    ('foo', 'foo')
])
def test_none_to_none(input_data, expected):
    assert none_to_none(input_data) == expected


@pytest.mark.parametrize('input_data, expected', [
    (datetime(2000, 2, 29), '2000-02-29'),
    ('1999-01-01', '1999-01-01'),
    (None, '1970-01-01')
])
def test_convert_time_to_str(input_data, expected):
    assert convert_time_to_str(input_data) == expected

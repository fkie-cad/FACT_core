import pytest
from datetime import datetime

from helperFunctions.dataConversion import make_bytes, make_unicode_string, make_dict_from_list, make_list_from_dict, list_of_lists_to_list_of_sets, \
    unify_string_list, string_list_to_list, get_value_of_first_key, none_to_none, list_of_sets_to_list_of_lists, remove_included_sets_from_list_of_sets, \
    build_time_dict, _fill_in_time_gaps, remove_uneccessary_spaces, convert_time_to_str


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


def test_make_dict_from_list():
    testlist = ['a', 'b']
    resultdict = make_dict_from_list(testlist)
    assert isinstance(resultdict, dict), 'type is not dict'
    assert resultdict == {'0': 'a', '1': 'b'}, 'dict not correct'


def test_make_list_from_dict():
    test_dict = {'a': 'abc', 'b': 'bcd'}
    result_list = make_list_from_dict(test_dict)
    assert isinstance(result_list, list), 'type is not list'
    result_list.sort()
    assert result_list == ['abc', 'bcd'], 'resulting list not correct'


def test_list_of_lists_to_list_of_sets():
    input_lists = [['a', 'b'], ['b', 'c']]
    result = list_of_lists_to_list_of_sets(input_lists)
    assert isinstance(result, list), 'result is not a list'
    for item in result:
        assert isinstance(item, set), '{} is not a set'.format(item)
    assert set('ab') in result, 'first set not found'


def test_list_of_sets_to_list_of_lists():
    input_sets = [{'a', 'b'}, {'b', 'c'}]
    result = list_of_sets_to_list_of_lists(input_sets)
    assert isinstance(result, list), 'result is not a list'
    for item in result:
        assert isinstance(item, list), '{} is not a list'.format(item)
    assert ['a', 'b'] in result, 'first list not found'
    assert list_of_sets_to_list_of_lists(None) == []


def test_unify_string_list():
    ids_a = 'a;b'
    ids_b = 'b;a'
    assert unify_string_list(ids_a) == 'a;b', 'compare id not correct'
    assert unify_string_list(ids_a) == unify_string_list(ids_b), 'compare ids not the same'


def test_string_list_to_list():
    assert string_list_to_list('a;b') == ['a', 'b']


@pytest.mark.parametrize('input_data, expected', [
    ({'b': 'b', 'c': 'c', 'a': 'a'}, 'a'),
    ({}, None)
])
def test_get_value_of_first_key(input_data, expected):
    assert get_value_of_first_key(input_data) == expected


def test_remove_included_sets_from_list_of_sets():
    test_sets = [{0, 1}, {0, 3}, {0, 2}, {0, 1, 2}, {1, 2, 3}, {1, 2}]
    remove_included_sets_from_list_of_sets(test_sets)
    assert {0, 3} in test_sets, 'subset removal deletes wrong sets'
    assert {0, 1} not in test_sets, 'subset removal omits sets'
    assert {1, 2} not in test_sets, 'subset removal omits duplicate subsets'


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
    (' test', 'test'),
    ('blah   blah ', 'blah blah')
])
def test_remove_uneccessary_spaces(input_data, expected):
    assert remove_uneccessary_spaces(input_data) == expected


@pytest.mark.parametrize('input_data, expected', [
    (datetime(2000, 2, 29), '2000-02-29'),
    ('1999-01-01', '1999-01-01'),
    (None, '1970-01-01')
])
def test_convert_time_to_str(input_data, expected):
    assert convert_time_to_str(input_data) == expected

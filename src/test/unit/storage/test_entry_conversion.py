from datetime import datetime
from decimal import Decimal

import pytest

from storage.db_interface_base import DbSerializationError
from storage.entry_conversion import sanitize, sanitize_list


@pytest.mark.parametrize(
    ('input_dict', 'expected'),
    [
        ({}, {}),
        ({'a': 1, 'b': '2'}, {'a': 1, 'b': '2'}),
        # null bytes and lone surrogates in strings are left untouched (handled by the DB types)
        ({'illegal': 'a\0b\0c'}, {'illegal': 'a\0b\0c'}),
        ({'nested': {'key': '\udcc4'}}, {'nested': {'key': '\udcc4'}}),
        (
            {'tuple': ('a', 'b'), 'nested': {'tuple': ('c', 'd')}, 'tuple_in_list': [('e', 'f')]},
            {'tuple': ['a', 'b'], 'nested': {'tuple': ['c', 'd']}, 'tuple_in_list': [['e', 'f']]},
        ),
        (
            {'tuple_in_list': [('a', 'b'), {'t': ('c',)}]},
            {'tuple_in_list': [['a', 'b'], {'t': ['c']}]},
        ),
        # scalars are passed through untouched
        ({'int': 1, 'float': 1.5, 'bool': True, 'none': None}, {'int': 1, 'float': 1.5, 'bool': True, 'none': None}),
    ],
)
def test_sanitize(input_dict, expected):
    sanitize(input_dict)
    assert input_dict == expected


def test_sanitize_converts_sets():
    input_dict = {'set': {'a', 'b'}, 'nested': {'set': {'c', 'd'}}}
    sanitize(input_dict)
    assert set(input_dict['set']) == {'a', 'b'}
    assert set(input_dict['nested']['set']) == {'c', 'd'}


def test_sanitize_converts_sets_in_lists():
    input_dict = {'set_in_list': [{'a', 'b'}], 'frozenset_in_list': [frozenset({'c'})]}
    sanitize(input_dict)
    assert set(input_dict['set_in_list'][0]) == {'a', 'b'}
    assert input_dict['frozenset_in_list'] == [['c']]


@pytest.mark.parametrize(
    ('value', 'expected_message'),
    [
        (b'bytes', "key 'a'"),
        ([b'bytes'], 'in list'),
        ({'nested': b'bytes'}, "key 'nested'"),
        (datetime(2020, 1, 1), "key 'a'"),
        ([datetime(2020, 1, 1)], 'in list'),
        (Decimal('1.5'), "key 'a'"),
        (object(), "key 'a'"),
    ],
)
def test_sanitize_rejects_non_json_types(value, expected_message):
    with pytest.raises(DbSerializationError, match=expected_message):
        sanitize({'a': value})


def test_sanitize_list_rejects_non_json_types():
    with pytest.raises(DbSerializationError, match='in list'):
        sanitize_list(['a', object()])


def test_sanitize_list_converts_containers():
    value = [('a', 'b'), {'c', 'd'}, frozenset({'e'}), 'g']
    sanitize_list(value)
    assert value[0] == ['a', 'b']
    assert set(value[1]) == {'c', 'd'}
    assert value[2] == ['e']
    assert value[3] == 'g'


@pytest.mark.parametrize(
    ('input_dict', 'expected'),
    [
        ({1: 'a'}, {'1': 'a'}),
        ({1.5: 'b'}, {'1.5': 'b'}),
        ({True: 'c'}, {'true': 'c'}),
        ({None: 'd'}, {'null': 'd'}),
        ({'outer': {2: 'x'}}, {'outer': {'2': 'x'}}),
    ],
)
def test_sanitize_coerces_scalar_keys(input_dict, expected):
    sanitize(input_dict)
    assert input_dict == expected


@pytest.mark.parametrize(
    'key',
    [(1, 2), b'k', datetime(2020, 1, 1), object()],
)
def test_sanitize_rejects_non_scalar_keys(key):
    with pytest.raises(DbSerializationError, match='key of type'):
        sanitize({key: 'a'})


def test_sanitize_rejects_non_scalar_keys_nested():
    with pytest.raises(DbSerializationError, match='key of type'):
        sanitize({'outer': {(1, 2): 'x'}})


def test_sanitize_rejects_non_scalar_keys_in_list():
    with pytest.raises(DbSerializationError, match='key of type'):
        sanitize_list([{'k': {(1, 2): 'x'}}])

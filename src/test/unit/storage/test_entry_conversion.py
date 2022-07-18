import pytest

from storage.entry_conversion import sanitize


@pytest.mark.parametrize('input_dict, expected', [
    ({}, {}),
    ({'a': 1, 'b': '2'}, {'a': 1, 'b': '2'}),
    ({'illegal': 'a\0b\0c'}, {'illegal': 'abc'}),
    ({'nested': {'key': 'a\0b\0c'}}, {'nested': {'key': 'abc'}}),
])
def test_sanitize(input_dict, expected):
    sanitize(input_dict)
    assert input_dict == expected

import pytest

from storage.entry_conversion import sanitize


@pytest.mark.parametrize(
    ('input_dict', 'expected'),
    [
        ({}, {}),
        ({'a': 1, 'b': '2'}, {'a': 1, 'b': '2'}),
        ({'illegal': 'a\0b\0c'}, {'illegal': 'abc'}),
        ({'nested': {'key': 'a\0b\0c'}}, {'nested': {'key': 'abc'}}),
        ({'ille\0gal': 'abc'}, {'illegal': 'abc'}),
        ({'nested': {'key\0': 'abc'}}, {'nested': {'key': 'abc'}}),
        ({'list': ['item\x001', {'list_in_dict': ['item2\0']}]}, {'list': ['item1', {'list_in_dict': ['item2']}]}),
        ({'vfp': {'123': ['123|/\udcc4\udcd6\udcdc\udce4\udcf6\udcfc\udcdf']}}, {'vfp': {'123': ['123|/???????']}}),
    ],
)
def test_sanitize(input_dict, expected):
    sanitize(input_dict)
    assert input_dict == expected

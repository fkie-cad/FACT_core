import pytest

from helperFunctions.virtual_file_path import join_virtual_path, split_virtual_path


@pytest.mark.parametrize(
    'virtual_path, expected_output',
    [
        ('', []),
        ('a|b|c', ['a', 'b', 'c']),
        ('|a|b|c|', ['a', 'b', 'c']),
    ],
)
def test_split_virtual_path(virtual_path, expected_output):
    assert split_virtual_path(virtual_path) == expected_output


@pytest.mark.parametrize(
    'element_list, expected_output',
    [
        ([], ''),
        (['a', 'b', 'c'], 'a|b|c'),
    ],
)
def test_join_virtual_path(element_list, expected_output):
    assert join_virtual_path(*element_list) == expected_output

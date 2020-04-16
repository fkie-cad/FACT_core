import pytest

from helperFunctions.virtual_file_path import (
    get_base_of_virtual_path, get_top_of_virtual_path, join_virtual_path, split_virtual_path
)


@pytest.mark.parametrize('virtual_path, expected_output', [
    ('', []),
    ('a|b|c', ['a', 'b', 'c']),
    ('|a|b|c|', ['a', 'b', 'c']),
])
def test_split_virtual_path(virtual_path, expected_output):
    assert split_virtual_path(virtual_path) == expected_output


@pytest.mark.parametrize('element_list, expected_output', [
    ([], ''),
    (['a', 'b', 'c'], 'a|b|c'),
])
def test_join_virtual_path(element_list, expected_output):
    assert join_virtual_path(*element_list) == expected_output


@pytest.mark.parametrize('virtual_path, expected_output', [
    ('root_uid', ''),
    ('root_uid|child_1_uid|child_2_uid|directory/file.type', 'root_uid|child_1_uid|child_2_uid'),
])
def test_get_base_of_virtual_path(virtual_path, expected_output):
    assert get_base_of_virtual_path(virtual_path) == expected_output


def test_get_top_of_virtual_path():
    assert get_top_of_virtual_path('foo|bar|test') == 'test', 'top should be test'

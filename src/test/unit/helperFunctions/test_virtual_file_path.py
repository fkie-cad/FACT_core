import pytest

from helperFunctions.virtual_file_path import (
    get_base_of_virtual_path, get_top_of_virtual_path, join_virtual_path, merge_vfp_lists, split_virtual_path
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
    ('', ''),
    ('root_uid', ''),
    ('root_uid|child_1_uid|child_2_uid|directory/file.type', 'root_uid|child_1_uid|child_2_uid'),
])
def test_get_base_of_virtual_path(virtual_path, expected_output):
    assert get_base_of_virtual_path(virtual_path) == expected_output


@pytest.mark.parametrize('virtual_path, expected_output', [
    ('', ''),
    ('root_uid', 'root_uid'),
    ('foo|bar|test', 'test'),
])
def test_get_top_of_virtual_path(virtual_path, expected_output):
    assert get_top_of_virtual_path(virtual_path) == expected_output


@pytest.mark.parametrize('old_vfp_list, new_vfp_list, expected_output', [
    ([], [], []),
    (['foo|/bar'], ['different|/base'], ['different|/base', 'foo|/bar']),
    (['foo|/old'], ['foo|/new'], ['foo|/new']),
    (
        ['base1|archive1|/file1', 'base1|archive1|/file2', 'base1|archive2|/file3', 'base2|archive3|/file4'],
        ['base1|archive1|/file5', 'base3|archive4|/file6'],
        ['base1|archive1|/file5', 'base1|archive2|/file3', 'base2|archive3|/file4', 'base3|archive4|/file6']
    ),
])
def test_merge_vfp_lists(old_vfp_list, new_vfp_list, expected_output):
    assert sorted(merge_vfp_lists(old_vfp_list, new_vfp_list)) == expected_output

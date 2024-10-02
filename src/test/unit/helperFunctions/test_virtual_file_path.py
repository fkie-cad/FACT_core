import pytest

from helperFunctions.virtual_file_path import filter_vpf_dict, get_paths_for_all_parents


@pytest.mark.parametrize(
    ('vfp_dict', 'expected'),
    [
        ({}, set()),
        ({'parent': ['path1', 'path2']}, {'path1', 'path2'}),
        ({'parent1': ['path1', 'path2'], 'parent2': ['path2', 'path3']}, {'path1', 'path2', 'path3'}),
    ],
)
def test_get_paths_for_all_parents(vfp_dict, expected):
    result = get_paths_for_all_parents(vfp_dict)
    assert len(result) == len(expected)
    assert set(result) == expected


@pytest.mark.parametrize(
    ('vfp_dict', 'allowed', 'expected'),
    [
        ({}, set(), {}),
        ({'parent_1': ['a', 'b'], 'parent_2': ['c', 'd']}, {'parent_1', 'parent_3'}, {'parent_1': ['a', 'b']}),
    ],
)
def test_filter_vpf_dict(vfp_dict, allowed, expected):
    assert filter_vpf_dict(vfp_dict, allowed) == expected

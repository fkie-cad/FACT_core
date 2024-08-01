import pytest

from helperFunctions.compare_sets import (
    _remove_duplicates_from_unhashable,
    remove_duplicates_from_list,
    substring_is_in_list,
)


@pytest.mark.parametrize(
    ('input_list', 'expected_output'),
    [
        (
            [[2, 4], [5, 9], [2, 5], [6, 7], [1, 3, 12], [4, 2], [1, 3, 12], [2, 4], [2, 4], [2, 4]],
            [[2, 4], [5, 9], [2, 5], [6, 7], [1, 3, 12], [4, 2]],
        ),
        ([{1, 2, 3}, {1, 2}, {2, 3}, {1, 2}, {3, 4}, {3, 2, 1}, {3, 2}, {4, 3}], [{1, 2, 3}, {1, 2}, {2, 3}, {3, 4}]),
    ],
)
def test_remove_duplicates_from_unhashable(input_list, expected_output):
    assert _remove_duplicates_from_unhashable(input_list) == expected_output, 'result not correct'


def test_substring_is_in_list():
    test_list = ['audio', 'video']
    super_string = 'audio/mp3'
    assert substring_is_in_list(super_string, test_list) is True
    unrelated_string = 'foobar'
    assert substring_is_in_list(unrelated_string, test_list) is False


@pytest.mark.parametrize(
    ('input_list', 'expected_output'),
    [
        ([], []),
        ([1, 2], [1, 2]),
        ([1, 1, 1, 2, 2, 3], [1, 2, 3]),
        ([[1, 2], [3, 4], [1, 2]], [[1, 2], [3, 4]]),  # unhashable
    ],
)
def test_remove_duplicates_from_list(input_list, expected_output):
    assert sorted(remove_duplicates_from_list(input_list)) == expected_output

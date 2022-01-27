import pytest

from helperFunctions.merge_generators import merge_lists, sum_up_lists


def test_sum_up_lists():
    list_a = [['a', 1], ['b', 5]]
    list_b = [['c', 3], ['b', 1]]
    result = sum_up_lists(list_a, list_b)
    assert len(result) == 3, 'number of entries not correct'
    assert ['a', 1] in result
    assert ['b', 6] in result
    assert ['c', 3] in result


@pytest.mark.parametrize('input_, expected_output', [
    ([[]], []),
    ([[], [], []], []),
    ([[1, 2, 3]], [1, 2, 3]),
    ([[1, 2, 3], [3, 4], [5]], [1, 2, 3, 4, 5]),
])
def test_merge_lists(input_, expected_output):
    assert merge_lists(*input_) == expected_output

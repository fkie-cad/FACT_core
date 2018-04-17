import pytest

from helperFunctions.statistic import calculate_total_files


@pytest.mark.parametrize('input_data, expected', [
    ([], 0),
    ([[('a', 1)], [('b', 2)]], 3),
    ([[('a', 1)], []], 1)
])
def test_calculate_total_files(input_data, expected):
    assert calculate_total_files(input_data) == expected

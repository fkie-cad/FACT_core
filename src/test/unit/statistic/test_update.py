import pytest

from statistic.update import StatisticUpdater

# pylint: disable=protected-access


def test_round():
    assert StatisticUpdater._round([('NX enabled', 1696)], 1903) == 0.89122


def test_convert_dict_list_to_list():
    test_list = [{'count': 1, '_id': 'A'}, {'count': 2, '_id': 'B'}, {'count': 3, '_id': None}]
    result = StatisticUpdater._convert_dict_list_to_list(test_list)
    assert isinstance(result, list), 'result is not a list'
    assert ['A', 1] in result
    assert ['B', 2] in result
    assert ['not available', 3] in result
    assert len(result) == 3, 'too many keys in the result'


@pytest.mark.parametrize('input_data, expected', [
    ([], 0),
    ([[('a', 1)], [('b', 2)]], 3),
    ([[('a', 1)], []], 1)
])
def test_calculate_total_files(input_data, expected):
    assert StatisticUpdater._calculate_total_files(input_data) == expected

from helperFunctions import merge_generators
from helperFunctions.merge_generators import sum_up_lists


class TestHelperFunctionsMergeGenerators:  # pylint: disable=no-self-use

    def test_sum_up_lists(self):
        list_a = [['a', 1], ['b', 5]]
        list_b = [['c', 3], ['b', 1]]
        result = sum_up_lists(list_a, list_b)
        assert len(result) == 3, 'number of entries not correct'
        assert ['a', 1] in result
        assert ['b', 6] in result
        assert ['c', 3] in result

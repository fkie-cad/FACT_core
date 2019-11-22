from helperFunctions import merge_generators
from helperFunctions.merge_generators import sum_up_lists


class TestHelperFunctionsMergeGenerators:  # pylint: disable=no-self-use

    def test_merge_generators(self):
        generator_a = range(3, 10)
        generator_b = range(15, 20)
        test_generated_list = list(generator_a) + list(generator_b)
        generator = merge_generators.merge_generators(generator_a, generator_b)
        generated_list = list(generator)
        assert len(test_generated_list) == len(generated_list)
        assert all([item in generated_list for item in test_generated_list])
        assert all([item in test_generated_list for item in generator])

    def test_sum_up_lists(self):
        list_a = [['a', 1], ['b', 5]]
        list_b = [['c', 3], ['b', 1]]
        result = sum_up_lists(list_a, list_b)
        assert len(result) == 3, 'number of entries not correct'
        assert ['a', 1] in result
        assert ['b', 6] in result
        assert ['c', 3] in result

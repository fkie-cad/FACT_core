import unittest
from helperFunctions import merge_generators
from helperFunctions.merge_generators import sum_up_lists


class TestHelperFunctionsMergeGenerators(unittest.TestCase):

    def test_merge_generators(self):
        generator_a = range(3, 10)
        generator_b = range(15, 20)
        test_generated_list = [i for i in generator_a] + [i for i in generator_b]
        generator = merge_generators.merge_generators(generator_a, generator_b)
        generated_list = [item for item in generator]
        self.assertEqual(len(test_generated_list), len(generated_list))
        self.assertTrue(all([item in generated_list for item in test_generated_list]))
        self.assertTrue(all([item in test_generated_list for item in generator]))

    def test_dict_to_sorted_tuples(self):
        test_dict = {"a": 2, "b": 1, "c": 3}
        self.assertEqual(
            merge_generators.dict_to_sorted_tuples(test_dict),
            [("c", 3), ("a", 2), ("b", 1)]
        )

    def test_sum_up_lists(self):
        a = [['a', 1], ['b', 5]]
        b = [['c', 3], ['b', 1]]
        result = sum_up_lists(a, b)
        self.assertEqual(len(result), 3, "number of entrys not correct")
        self.assertIn(['a', 1], result)
        self.assertIn(['b', 6], result)
        self.assertIn(['c', 3], result)

import unittest
from datetime import datetime

from helperFunctions.dataConversion import make_bytes, make_unicode_string, make_dict_from_list, make_list_from_dict, list_of_lists_to_list_of_sets, \
    unify_string_list, string_list_to_list, get_value_of_first_key, none_to_none, list_of_sets_to_list_of_lists, remove_included_sets_from_list_of_sets, \
    build_time_dict, _fill_in_time_gaps, remove_uneccessary_spaces, convert_time_to_str


class TestMakeBytes(unittest.TestCase):

    def check_type_and_content(self, input_data):
        self.assertIsInstance(make_bytes(input_data), bytes, 'type is correct')
        self.assertEqual(make_bytes(input_data), b'test string', 'content correct')

    def test_make_bytes_from_string(self):
        string_object = 'test string'
        self.check_type_and_content(string_object)

    def test_make_bytes_from_bytes(self):
        bytes_object = b'test string'
        self.check_type_and_content(bytes_object)

    def test_make_bytes_from_other_object(self):
        int_list = [116, 101, 115, 116, 32, 115, 116, 114, 105, 110, 103]
        self.check_type_and_content(int_list)


class TestMakeUnicodeString(unittest.TestCase):

    def check_type_and_content(self, input_data):
        self.assertIsInstance(make_unicode_string(input_data), str, 'type is correct')
        self.assertEqual(make_unicode_string(input_data), 'test string', 'content correct')

    def test_string_from_string(self):
        test_string = 'test string'
        self.check_type_and_content(test_string)

    def test_string_from_bytes(self):
        test_string = b'test string'
        self.check_type_and_content(test_string)

    def test_string_from_bytes_unicode_character(self):
        test_string = b'\xc3\xbc test string'
        result = make_unicode_string(test_string)
        self.assertEqual(result, 'ü test string', 'string not correct')

    def test_string_from_bytes_decoding_error(self):
        test_string = b'\xf5 test string'
        result = make_unicode_string(test_string)
        self.assertEqual(result, '� test string', 'string not correct')

    def test_string_from_other_object(self):
        test_string = ['test string']
        result = make_unicode_string(test_string)
        self.assertEqual(result, '[\'test string\']', 'string not correct')


class TestListConversion(unittest.TestCase):

    def test_make_dict_from_list(self):
        testlist = ['a', 'b']
        resultdict = make_dict_from_list(testlist)
        self.assertIsInstance(resultdict, dict, 'type is not dict')
        self.assertEqual(resultdict, {'0': 'a', '1': 'b'}, 'dict not correct')

    def test_make_list_from_dict(self):
        test_dict = {'a': 'abc', 'b': 'bcd'}
        result_list = make_list_from_dict(test_dict)
        self.assertIsInstance(result_list, list, 'type is not list')
        result_list.sort()
        self.assertEqual(result_list, ['abc', 'bcd'], 'resulting list not correct')

    def test_list_of_lists_to_list_of_sets(self):
        input_lists = [['a', 'b'], ['b', 'c']]
        result = list_of_lists_to_list_of_sets(input_lists)
        self.assertIsInstance(result, list, 'result is not a list')
        for item in result:
            self.assertIsInstance(item, set, '{} is not a set'.format(item))
        self.assertIn(set('ab'), result, 'first set not found')

    def test_list_of_sets_to_list_of_lists(self):
        input_sets = [{'a', 'b'}, {'b', 'c'}]
        result = list_of_sets_to_list_of_lists(input_sets)
        self.assertIsInstance(result, list, 'result is not a list')
        for item in result:
            self.assertIsInstance(item, list, '{} is not a list'.format(item))
        self.assertIn(['a', 'b'], result, 'first list not found')

        assert list_of_sets_to_list_of_lists(None) == []

    def test_unify_string_list(self):
        ids_a = 'a;b'
        ids_b = 'b;a'
        self.assertEqual(unify_string_list(ids_a), 'a;b', 'compare id not correct')
        self.assertEqual(unify_string_list(ids_a), unify_string_list(ids_b), 'compare ids not the same')

    def test_string_list_to_list(self):
        self.assertEqual(string_list_to_list('a;b'), ['a', 'b'])

    def test_get_value_of_first_key(self):
        test_dict = {'b': 'b', 'c': 'c', 'a': 'a'}
        self.assertEqual(get_value_of_first_key(test_dict), 'a', 'value not correct')
        self.assertEqual(get_value_of_first_key({}), None, 'empty dict should result in None output')


class TestMisc(unittest.TestCase):

    def test_none_to_none(self):
        self.assertIsNone(none_to_none(None), 'none input not correct')
        self.assertIsNone(none_to_none('None'), 'none string not crorrect')
        self.assertEqual(none_to_none('foo'), 'foo', 'non none string')

    def test_remove_included_sets_from_list_of_sets(self):
        test_sets = [{0, 1}, {0, 3}, {0, 2}, {0, 1, 2}, {1, 2, 3}, {1, 2}]
        remove_included_sets_from_list_of_sets(test_sets)
        self.assertIn({0, 3}, test_sets, 'subset removal deletes wrong sets')
        self.assertNotIn({0, 1}, test_sets, 'subset removal omits sets')
        self.assertNotIn({1, 2}, test_sets, 'subset removal omits duplicate subsets')

    def test_remove_uneccessary_spaces(self):
        self.assertEqual(remove_uneccessary_spaces(' test'), 'test')
        self.assertEqual(remove_uneccessary_spaces('blah   blah '), 'blah blah')

    def test_build_time_dict(self):
        test_input = [{'_id': {'month': 12, 'year': 2016}, 'count': 10},
                      {'_id': {'month': 1, 'year': 2017}, 'count': 8}]
        expected_result = {2016: {12: 10}, 2017: {1: 8}}
        self.assertEqual(build_time_dict(test_input), expected_result)

    def test_fill_in_time_gaps(self):
        test_input = {2016: {11: 10}, 2017: {2: 8}}
        expected_result = {2016: {11: 10, 12: 0}, 2017: {1: 0, 2: 8}}
        _fill_in_time_gaps(test_input)
        self.assertEqual(test_input, expected_result)

    def test_convert_time_to_str(self):
        date = datetime(2000, 2, 29)
        assert convert_time_to_str(date) == '2000-02-29', 'datetime object conversion not successful'
        assert convert_time_to_str('1999-01-01') == '1999-01-01'
        assert convert_time_to_str(None) == '1970-01-01'


if __name__ == '__main__':
    unittest.main()

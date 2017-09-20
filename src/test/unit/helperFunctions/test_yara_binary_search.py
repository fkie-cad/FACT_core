import unittest

from helperFunctions import yara_binary_search, fileSystem
from os import path


class TestHelperFunctionsYaraBinarySearch(unittest.TestCase):

    def setUp(self):
        self.yara_rule = b'rule test_rule {strings: $a = "test1234" condition: $a}'
        test_path = path.join(fileSystem.get_test_data_dir(), "binary_search_test")
        test_config = {'data_storage': {'firmware_file_storage_directory': test_path}}
        self.yara_binary_scanner = yara_binary_search.YaraBinarySearchScanner(test_config)

    def test_get_binary_search_result(self):
        result = self.yara_binary_scanner.get_binary_search_result(self.yara_rule)
        self.assertEqual(result, {'test_rule': ['binary_search_test']})

    def test_eliminate_duplicates(self):
        test_dict = {1: [1, 2, 3, 3], 2: [1, 1, 2, 3]}
        self.yara_binary_scanner._eliminate_duplicates(test_dict)
        self.assertEqual(test_dict, {1: [1, 2, 3], 2: [1, 2, 3]})

    def test_parse_raw_result(self):
        raw_result = b"rule_1 match_1\nrule_1 match_2\nrule_2 match_1"
        result = self.yara_binary_scanner._parse_raw_result(raw_result)
        self.assertEqual(result, {'rule_1': ['match_1', 'match_2'], 'rule_2': ['match_1']})

    def test_execute_yara_search(self):
        test_rule_path = path.join(fileSystem.get_test_data_dir(), "yara_binary_search_test_rule")
        result = self.yara_binary_scanner._execute_yara_search(test_rule_path)
        self.assertTrue(b"test_rule" in result)

import unittest
from os import path
from subprocess import CalledProcessError
from unittest import mock
from unittest.mock import patch

import pytest

from fact.helperFunctions import yara_binary_search
from fact.test.common_helper import get_test_data_dir

TEST_FILE_1 = 'binary_search_test'
TEST_FILE_2 = 'binary_search_test_2'
TEST_FILE_3 = 'binary_search_test_3'


class MockCommonDbInterface:
    @staticmethod
    def get_all_files_in_fw(uid):
        if uid == 'single_firmware':
            return [TEST_FILE_2, TEST_FILE_3]
        return []


def mock_check_output(call, *_, shell=True, stderr=None, **__):  # noqa: ARG001
    raise CalledProcessError(1, call, b'', stderr)


@pytest.mark.backend_config_overwrite(
    {'firmware_file_storage_directory': path.join(get_test_data_dir(), TEST_FILE_1)},  # noqa: PTH118
)
class TestHelperFunctionsYaraBinarySearch(unittest.TestCase):
    @mock.patch('helperFunctions.yara_binary_search.DbInterfaceCommon', MockCommonDbInterface)
    def setUp(self):
        self.yara_rule = b'rule test_rule {strings: $a = "test1234" condition: $a}'
        self.yara_binary_scanner = yara_binary_search.YaraBinarySearchScanner()

    def test_get_binary_search_result(self):
        result = self.yara_binary_scanner.get_binary_search_result((self.yara_rule, None))
        assert result == {'test_rule': [TEST_FILE_1]}

    def test_get_binary_search_result_for_single_firmware(self):
        yara_rule = b'rule test_rule_2 {strings: $a = "TEST_STRING!" condition: $a}'
        result = self.yara_binary_scanner.get_binary_search_result((yara_rule, 'single_firmware'))
        assert result == {'test_rule_2': [TEST_FILE_2]}

        result = self.yara_binary_scanner.get_binary_search_result((yara_rule, 'foobar'))
        assert result == {}

    def test_get_binary_search_rule_error(self):
        result = self.yara_binary_scanner.get_binary_search_result((b'no valid rule', 'foobar'))
        assert isinstance(result, str)
        assert 'There seems to be an error in the rule file' in result

    @patch('helperFunctions.yara_binary_search.subprocess.run', side_effect=mock_check_output)
    def test_get_binary_search_yara_error(self, _):  # noqa: PT019
        result = self.yara_binary_scanner.get_binary_search_result((self.yara_rule, None))
        assert isinstance(result, str)
        assert 'Error when calling YARA' in result

    def test_eliminate_duplicates(self):
        test_dict = {1: [1, 2, 3, 3], 2: [1, 1, 2, 3]}
        self.yara_binary_scanner._eliminate_duplicates(test_dict)
        assert test_dict == {1: [1, 2, 3], 2: [1, 2, 3]}

    def test_parse_raw_result(self):
        raw_result = 'rule_1 match_1\nrule_1 match_2\nrule_2 match_1'
        result = self.yara_binary_scanner._parse_raw_result(raw_result)
        assert result == {'rule_1': ['match_1', 'match_2'], 'rule_2': ['match_1']}

    def test_execute_yara_search(self):
        test_rule_path = path.join(get_test_data_dir(), 'yara_binary_search_test_rule')  # noqa: PTH118
        result = self.yara_binary_scanner._execute_yara_search(test_rule_path)
        assert 'test_rule' in result

    def test_execute_yara_search_for_single_file(self):
        test_rule_path = path.join(get_test_data_dir(), 'yara_binary_search_test_rule')  # noqa: PTH118
        result = self.yara_binary_scanner._execute_yara_search(
            test_rule_path,
            target_path=path.join(get_test_data_dir(), TEST_FILE_1, TEST_FILE_1),  # noqa: PTH118
        )
        assert 'test_rule' in result

    def test_get_file_paths_of_files_included_in_fo(self):
        result = self.yara_binary_scanner._get_file_paths_of_files_included_in_fw('single_firmware')
        assert len(result) == 2  # noqa: PLR2004
        assert path.basename(result[0]) == TEST_FILE_2  # noqa: PTH119
        assert path.basename(result[1]) == TEST_FILE_3  # noqa: PTH119

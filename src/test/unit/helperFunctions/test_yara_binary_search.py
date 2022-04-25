# pylint: disable=no-self-use
# pylint: disable=protected-access
from os import path
from subprocess import CalledProcessError

import pytest

from helperFunctions import yara_binary_search
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order

TEST_DATA_DIR = path.join(get_test_data_dir(), 'binary_search_test')
TEST_FILE_1 = 'binary_search_test'
TEST_FILE_2 = 'binary_search_test_2'
TEST_FILE_3 = 'binary_search_test_3'


class MockCommonDbInterface:
    def __init__(self, config):
        self.config = config

    @staticmethod
    def get_all_files_in_fw(uid):
        if uid == 'single_firmware':
            return [TEST_FILE_2, TEST_FILE_3]
        return []


def mock_check_output(call, *_, shell=True, stderr=None, **__):
    raise CalledProcessError(1, call, b'', stderr)


@pytest.fixture
def yara_binary_scanner(monkeypatch, cfg_tuple):
    _, configparser_cfg = cfg_tuple
    yara_binary_search_scanner = yara_binary_search.YaraBinarySearchScanner(configparser_cfg)
    monkeypatch.setattr(yara_binary_search_scanner, 'db', MockCommonDbInterface(configparser_cfg))
    yield yara_binary_search_scanner


@pytest.mark.cfg_defaults({
    'data-storage': {
        'firmware-file-storage-directory': TEST_DATA_DIR,
    }
})
class TestHelperFunctionsYaraBinarySearch:
    yara_rule = b'rule test_rule {strings: $a = "test1234" condition: $a}'

    def test_get_binary_search_result(self, yara_binary_scanner):
        result = yara_binary_scanner.get_binary_search_result((self.yara_rule, None))
        assert result == {'test_rule': [TEST_FILE_1]}

    def test_get_binary_search_result_for_single_firmware(self, yara_binary_scanner):
        yara_rule = b'rule test_rule_2 {strings: $a = "TEST_STRING!" condition: $a}'
        result = yara_binary_scanner.get_binary_search_result((yara_rule, 'single_firmware'))
        assert result == {'test_rule_2': [TEST_FILE_2]}

        result = yara_binary_scanner.get_binary_search_result((yara_rule, 'foobar'))
        assert result == {}

    def test_get_binary_search_rule_error(self, yara_binary_scanner):
        result = yara_binary_scanner.get_binary_search_result((b'no valid rule', 'foobar'))
        assert isinstance(result, str)
        assert 'There seems to be an error in the rule file' in result

    def test_get_binary_search_yara_error(self, monkeypatch, yara_binary_scanner):
        monkeypatch.setattr('helperFunctions.yara_binary_search.subprocess.run', mock_check_output)
        result = yara_binary_scanner.get_binary_search_result((self.yara_rule, None))
        assert isinstance(result, str)
        assert 'Error when calling YARA' in result

    def test_eliminate_duplicates(self, yara_binary_scanner):
        test_dict = {1: [1, 2, 3, 3], 2: [1, 1, 2, 3]}
        yara_binary_scanner._eliminate_duplicates(test_dict)
        assert test_dict == {1: [1, 2, 3], 2: [1, 2, 3]}

    def test_parse_raw_result(self, yara_binary_scanner):
        raw_result = 'rule_1 match_1\nrule_1 match_2\nrule_2 match_1'
        result = yara_binary_scanner._parse_raw_result(raw_result)
        assert result == {'rule_1': ['match_1', 'match_2'], 'rule_2': ['match_1']}

    def test_execute_yara_search(self, yara_binary_scanner):
        test_rule_path = path.join(get_test_data_dir(), 'yara_binary_search_test_rule')
        result = yara_binary_scanner._execute_yara_search(test_rule_path)
        assert 'test_rule' in result

    def test_execute_yara_search_for_single_file(self, yara_binary_scanner):
        test_rule_path = path.join(get_test_data_dir(), 'yara_binary_search_test_rule')
        result = yara_binary_scanner._execute_yara_search(
            test_rule_path,
            target_path=path.join(TEST_DATA_DIR, TEST_FILE_1)
        )
        assert 'test_rule' in result

    def test_get_file_paths_of_files_included_in_fo(self, yara_binary_scanner):
        result = yara_binary_scanner._get_file_paths_of_files_included_in_fw('single_firmware')
        assert len(result) == 2
        assert path.basename(result[0]) == TEST_FILE_2
        assert path.basename(result[1]) == TEST_FILE_3

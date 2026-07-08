import pytest

from helperFunctions import yara_binary_search
from test.common_helper import get_test_data_dir

TEST_FILE_1 = 'binary_search_test'
TEST_FILE_2 = 'binary_search_test_2'
TEST_FILE_3 = 'binary_search_test_3'


class MockCommonDbInterface:
    @staticmethod
    def get_all_files_in_fw(uid):
        if uid == 'single_firmware':
            return [TEST_FILE_2, TEST_FILE_3]
        return []


@pytest.fixture
def yara_binary_scanner():
    return yara_binary_search.YaraBinarySearchScanner(MockCommonDbInterface)


@pytest.mark.backend_config_overwrite(
    {'firmware_file_storage_directory': str(get_test_data_dir() / TEST_FILE_1)},
)
class TestHelperFunctionsYaraBinarySearch:
    def test_get_binary_search_result(self, yara_binary_scanner):
        yara_rule = b'rule test_rule {strings: $a = "test1234" condition: $a}'
        result = yara_binary_scanner.get_binary_search_result((yara_rule, None))
        assert TEST_FILE_1 in result
        assert len(result[TEST_FILE_1]) > 0
        assert result == {
            'binary_search_test': {'test_rule': [{'condition': '$a', 'match': 'test1234', 'offset': '0x9'}]}
        }

    def test_get_binary_search_result_for_single_firmware(self, yara_binary_scanner):
        yara_rule = b'rule test_rule_2 {strings: $a = "TEST_STRING!" condition: $a}'
        result = yara_binary_scanner.get_binary_search_result((yara_rule, 'single_firmware'))
        assert TEST_FILE_2 in result
        assert len(result[TEST_FILE_2]) > 0
        assert result == {
            'binary_search_test_2': {'test_rule_2': [{'condition': '$a', 'match': 'TEST_STRING!', 'offset': '0x17'}]}
        }

        result = yara_binary_scanner.get_binary_search_result((yara_rule, 'foobar'))
        assert result == {}

    def test_get_binary_search_rule_error(self, yara_binary_scanner):
        result = yara_binary_scanner.get_binary_search_result((b'no valid rule', 'foobar'))
        assert isinstance(result, str)
        assert 'There seems to be an error in the rule file' in result

    def test_get_file_paths_of_files_included_in_fo(self, yara_binary_scanner):
        result = yara_binary_scanner._get_file_paths_of_files_included_in_fw('single_firmware')
        assert len(result) == 2
        assert result[0].endswith(TEST_FILE_2)
        assert result[1].endswith(TEST_FILE_3)

from helperFunctions.binwalk import get_list_of_binwalk_signatures
from helperFunctions.fileSystem import get_test_data_dir
import os
from common_helper_files.fail_safe_file_operations import get_binary_from_file

TEST_FILE = os.path.join(get_test_data_dir(), 'binwalk.out')


def test_get_list_of_binwalk_signatures():
    binwalk_output = get_binary_from_file(TEST_FILE).decode('utf-8')
    result = get_list_of_binwalk_signatures(binwalk_output)
    assert len(result) == 8
    assert '0             0x0             ELF, 64-bit LSB executable, AMD x86-64, version 1 (SYSV)' in result

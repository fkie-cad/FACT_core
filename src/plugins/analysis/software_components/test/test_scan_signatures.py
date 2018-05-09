import os

from common_helper_files import get_dir_of_file

from ..internal.scan_signatures import get_scanned_software

TEST_SIGNATURE_DIR = os.path.join(get_dir_of_file(__file__), './data')


def test_get_scanned_software():
    assert get_scanned_software(TEST_SIGNATURE_DIR + '/test_signature.yara') == ['OS1', 'OS2']

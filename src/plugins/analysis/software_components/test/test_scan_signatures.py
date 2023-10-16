from __future__ import annotations

import os
from tempfile import NamedTemporaryFile

from common_helper_files import get_dir_of_file

from ..internal.extract_os_names import extract_names, get_software_names

TEST_SIGNATURE_FILE = os.path.join(get_dir_of_file(__file__), './data/signatures/test_signature.yara')  # noqa: PTH118


def test_get_scanned_software():
    assert get_software_names(TEST_SIGNATURE_FILE) == ['OS1', 'OS2']


def test_extract_names():
    target_file = NamedTemporaryFile()

    extract_names(TEST_SIGNATURE_FILE, target_file.name)

    with open(target_file.name) as fd:  # noqa: PTH123
        data = fd.read()

    assert data == 'OS_LIST = ["OS1", "OS2"]\n'

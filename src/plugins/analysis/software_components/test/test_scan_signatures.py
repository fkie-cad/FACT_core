from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

from ..internal.extract_os_names import extract_names, get_software_names

TEST_SIGNATURE_FILE = Path(__file__).parent / 'data/signatures/test_signature.yara'


def test_get_scanned_software():
    assert get_software_names(TEST_SIGNATURE_FILE) == ['OS1', 'OS2']


def test_extract_names():
    with NamedTemporaryFile() as target_file:
        path = Path(target_file.name)
        extract_names(TEST_SIGNATURE_FILE, path)
        data = path.read_text()

    assert data == 'OS_LIST = ["OS1", "OS2"]\n'

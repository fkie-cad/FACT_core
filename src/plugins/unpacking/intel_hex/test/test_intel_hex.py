import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from intelhex import IntelHexError

from helperFunctions.fileSystem import get_test_data_dir
from plugins.unpacking.intel_hex.code.intel_hex import unpack_function
from test.unit.unpacker.test_unpacker import TestUnpackerBase

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


def i_always_crash(*args, **kwargs):
    raise IntelHexError()


class TestIntelHex(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('firmware/intel-hex', 'IntelHEX')

    def test_extraction(self):
        files, meta_data = self.unpacker.extract_files_from_file(str(Path(TEST_DATA_DIR, 'testfile.hex')), self.tmp_dir.name)
        assert len(files) == 1
        content = Path(files[0]).read_text()
        assert 'test string' in content
        assert 'Success' in meta_data['output']

    def test_extraction_bad_file(self):
        file_path = str(Path(get_test_data_dir(), 'test_data_file.bin'))

        with TemporaryDirectory() as tmp_dir:
            meta_data = unpack_function(file_path, tmp_dir)

        assert 'Invalid' in meta_data['output']

    @patch('intelhex.IntelHex.tofile', i_always_crash)
    def test_extraction_decoding_error(self):
        file_path = str(Path(TEST_DATA_DIR, 'testfile.hex'))

        with TemporaryDirectory() as tmp_dir:
            meta_data = unpack_function(file_path, tmp_dir)

        assert 'Unknown' in meta_data['output']

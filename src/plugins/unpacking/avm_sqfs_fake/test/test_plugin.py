import os
from common_helper_files import get_binary_from_file

from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestAvmFakeSqFs(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('filesystem/avm-sqfs-fake', 'avm_sqfs_fake')

    def test_extraction(self):
        in_file = os.path.join(TEST_DATA_DIR, 'fake.sqfs')
        self.unpacker.extract_files_from_file(in_file, self.tmp_dir.name)
        result = get_binary_from_file(os.path.join(self.tmp_dir.name, 'image.ext2'))
        assert result == b'Test File' + 247 * b'\x00'  # padding because of 256 bytes block size

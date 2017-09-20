import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestSquashUnpacker(TestUnpackerBase):
    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('filesystem/squashfs', 'SquashFS')

    def test_extraction_sqfs(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'sqfs.img'), additional_prefix_folder='faf_extracted')

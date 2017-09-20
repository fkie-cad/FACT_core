import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestYaffsUnpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('filesystem/yaffs', 'YAFFS')

    def test_extraction_big_endian(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'yaffs2_be.img'), additional_prefix_folder='')

    def test_extraction_little_endian(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'yaffs2_le.img'), additional_prefix_folder='')

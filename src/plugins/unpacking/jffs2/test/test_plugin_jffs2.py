import os

from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class Test_JFFS2_Unpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('filesystem/jffs2', 'JFFS2')
        self.check_unpacker_selection('filesystem/jffs2-big', 'JFFS2')

    def test_extraction_little(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'jffs2_be.img'), additional_prefix_folder='jffs-root/fs_1')

    def test_extraciton_big(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'jffs2_le.img'), additional_prefix_folder='jffs-root/fs_1')

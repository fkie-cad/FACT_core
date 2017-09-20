import os

from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestGenericFsUnpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('filesystem/cramfs', 'genericFS')
        self.check_unpacker_selection('filesystem/romfs', 'genericFS')
        self.check_unpacker_selection('filesystem/btrfs', 'genericFS')
        self.check_unpacker_selection('filesystem/ext2', 'genericFS')
        self.check_unpacker_selection('filesystem/ext3', 'genericFS')
        self.check_unpacker_selection('filesystem/ext4', 'genericFS')
        self.check_unpacker_selection('filesystem/dosmbr', 'genericFS')
        self.check_unpacker_selection('filesystem/hfs', 'genericFS')
        self.check_unpacker_selection('filesystem/jfs', 'genericFS')
        self.check_unpacker_selection('filesystem/minix', 'genericFS')
        self.check_unpacker_selection('filesystem/reiserfs', 'genericFS')
        self.check_unpacker_selection('filesystem/udf', 'genericFS')
        self.check_unpacker_selection('filesystem/xfs', 'genericFS')

    def test_extraction_cramfs(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'cramfs.img'))

    def test_extraction_romfs(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'romfs.img'))

    def test_extraction_btrfs(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'btrfs.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_ext2(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'ext2.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_ext3(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'ext3.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_ext4(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'ext4.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_fat(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'fat.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_msdos(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'msdos.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_ntfs(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'ntfs.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_hfs(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'hfs.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_jfs(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'jfs.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_minix(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'minix.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_reiserfs(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'reiserfs.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_udf(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'udf.img'),
                                                    additional_prefix_folder='get_files_test')

    def test_extraction_xfs(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'xfs.img'),
                                                    additional_prefix_folder='get_files_test')

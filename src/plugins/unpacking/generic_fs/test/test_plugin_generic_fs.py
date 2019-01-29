import os
from pathlib import Path

from test.unit.unpacker.test_unpacker import TestUnpackerBase
from ..code.generic_fs import _extract_loop_devices

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
KPARTX_OUTPUT = '''
add map loop7p1 (253:0): 0 7953 linear 7:7 2048
add map loop7p2 (253:1): 0 10207 linear 7:7 10240
'''


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

    def test_extract_multiple_partitions(self):
        files, meta_data = self.unpacker.extract_files_from_file(str(Path(TEST_DATA_DIR, 'mbr.img')), self.tmp_dir.name)

        expected = [
            str(Path(self.tmp_dir.name, *file_path)) for file_path in [
                ('partition_0', 'test_data_file.bin'),
                ('partition_1', 'yara_test_file'),
                ('partition_2', 'testfile1')
            ]
        ]

        assert 'output' in meta_data
        assert len(files) == 3, 'file number incorrect'
        assert sorted(files) == sorted(expected), 'wrong files extracted'


def test_extract_loop_devices():
    loop_devices = _extract_loop_devices(KPARTX_OUTPUT)
    assert loop_devices
    assert loop_devices == ['loop7p1', 'loop7p2']

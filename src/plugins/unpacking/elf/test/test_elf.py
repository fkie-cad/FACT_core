import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestElfUnpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('application/x-executable', 'ELF')

    def test_extraction_with_normal_elf(self):
        files, meta_data = self.unpacker.extract_files_from_file(os.path.join(TEST_DATA_DIR, 'test'), self.tmp_dir.name)
        assert not files, 'no file should be extracted'
        assert 'Will not be extracted' in meta_data['output']

    def test_with_self_extracting_archives(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'test_sfx.elf'), additional_prefix_folder='get_files_test', output=True)
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'test_sfx.exe'), additional_prefix_folder='get_files_test', output=True)

import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestSfxUnpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        for mime in ['application/x-executable', 'application/x-dosexec']:
            self.check_unpacker_selection(mime, 'SFX')

    def test_normal_elf_is_skipped(self):
        files, meta_data = self.unpacker.extract_files_from_file(os.path.join(TEST_DATA_DIR, 'test_elf_normal'), self.tmp_dir.name)
        assert not files, 'no file should be extracted'
        assert 'will not be extracted' in meta_data['output']

    def test_normal_pe_with_rsrc_directory(self):
        files, meta_data = self.unpacker.extract_files_from_file(os.path.join(TEST_DATA_DIR, 'test_rsrc'), self.tmp_dir.name)
        assert not files, 'no file should be extracted'
        assert 'will not be extracted' in meta_data['output']

    def test_with_self_extracting_archives(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'test_elf_sfx'), additional_prefix_folder='get_files_test', output=True)
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'test_pe_sfx'), additional_prefix_folder='get_files_test', output=True)

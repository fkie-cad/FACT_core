import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestUEFIUnpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('firmware/uefi', 'UEFI')

    def test_extraction(self):
        in_file = os.path.join(TEST_DATA_DIR, 'UEFI.CAP')
        files, meta_data = self.unpacker.extract_files_from_file(in_file, self.tmp_dir.name)
        self.assertEqual(len(files), 1395, 'file number incorrect')
        self.assertIn('output', meta_data)

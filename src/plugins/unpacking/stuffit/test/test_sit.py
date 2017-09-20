import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestSitUnpacker(TestUnpackerBase):
    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('application/x-stuffit', 'StuffItFile')
        self.check_unpacker_selection('application/x-sit', 'StuffItFile')
        self.check_unpacker_selection('application/x-stuffitx', 'StuffItFile')
        self.check_unpacker_selection('application/x-sitx', 'StuffItFile')

    def test_extraction(self):
        in_file = os.path.join(TEST_DATA_DIR, 'test.sitx')
        files, meta_data = self.unpacker.extract_files_from_file(in_file, self.tmp_dir.name)
        self.assertEqual(len(files), 1, 'file number incorrect')
        self.assertEqual(files, ['{}/Sampling SIM.app.rsrc'.format(self.tmp_dir.name)], 'not all files found')
        self.assertIn('output', meta_data, 'output meta missing')

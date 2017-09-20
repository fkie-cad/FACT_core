import os

from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class Test_UBIFS_Unpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('firmware/ubi-image', 'UBI-Image')

    def test_extraction(self):
        test_file = os.path.join(TEST_DATA_DIR, 'ubi.img')
        files, meta_data = self.unpacker.extract_files_from_file(test_file, self.tmp_dir.name)
        self.assertEqual(len(files), 1, 'file number incorrect')
        self.assertEqual(meta_data['plugin_used'], 'UBI-Image', 'wrong plugin selected')

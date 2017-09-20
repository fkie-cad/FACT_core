import os
import zipfile

from test.unit.unpacker.test_unpacker import TestUnpackerBase

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestUntrxUnpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('firmware/trx', 'untrx')

    def test_extraction_trx(self):
        files, meta_data = self.unpacker.extract_files_from_file(os.path.join(TEST_DATA_DIR, 'trx.img'), self.tmp_dir.name)
        self.assertEqual(len(files), 1)
        with zipfile.ZipFile(files[0], 'r') as extracted_file:
            included_file_list = [os.path.basename(f) for f in extracted_file.namelist() if os.path.basename(f)]
            for f in ['test file 3_.txt', 'testfile1', 'testfile2']:
                self.assertIn(f, included_file_list)

        files, meta_data = self.unpacker.extract_files_from_file(os.path.join(TEST_DATA_DIR, 'netgear.trx'), self.tmp_dir.name)
        self.assertEqual(len(files), 2)
        included_file_list = [os.path.basename(f) for f in files if os.path.basename(f)]
        for f in included_file_list:
            self.assertIn(f, ['squashfs-lzma-image-x_x', 'segment1'])

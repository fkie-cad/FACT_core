import os

from test.unit.unpacker.test_unpacker import TestUnpackerBase

TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestUnpackerPluginDsk(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        mimes = ['firmware/dsk1.0-extended']
        for item in mimes:
            self.check_unpacker_selection(item, 'DSK-extended')

    def test_extraction(self):
        test_file = os.path.join(TEST_DATA_DIR, 'test.dsk_ext')
        files, meta_data = self.unpacker.extract_files_from_file(test_file, self.tmp_dir.name)
        self.assertEqual(len(files), 1, 'Number of extracted files not correct')
        self.assertEqual(meta_data['payload size'], 151256, 'meta data not set correctly')
        self.assertEqual(meta_data['encoding_overhead'], 0.33, 'encoding overhead not correct')

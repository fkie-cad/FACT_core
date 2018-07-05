import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestSevenZUnpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        mimes = ['application/x-7z-compressed', 'application/x-lzma', 'application/zip', 'application/x-zip-compressed']
        for item in mimes:
            self.check_unpacker_selection(item, '7z')

    def test_extraction_sevenz(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, "test.7z"), additional_prefix_folder="get_files_test", output=True)

    def test_extraction_password(self):
        meta = self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, "test_password.7z"), additional_prefix_folder="get_files_test", output=True)
        self.assertEqual(meta['password'], 'test', "password info not set")

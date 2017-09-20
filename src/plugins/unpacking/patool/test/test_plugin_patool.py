import os
from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestPaToolUnpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('application/vnd.ms-cab-compressed', 'PaTool')

    def test_extraction(self):
        in_files = ['test.cab', 'test.zoo', 'test.tar.bz2', 'test.tar.zip']
        for in_file in in_files:
            self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, in_file), additional_prefix_folder='get_files_test', output=False)

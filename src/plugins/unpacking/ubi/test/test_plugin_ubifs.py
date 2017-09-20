import os

from test.unit.unpacker.test_unpacker import TestUnpackerBase


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class Test_UBIFS_Unpacker(TestUnpackerBase):

    def test_unpacker_selection_generic(self):
        self.check_unpacker_selection('filesystem/ubifs', 'UBIFS')

    def test_extraction(self):
        self.check_unpacking_of_standard_unpack_set(os.path.join(TEST_DATA_DIR, 'test.ubifs'), additional_prefix_folder='')

import os
import gc
import unittest

from helperFunctions.hash import get_sha256
from helperFunctions.fileSystem import get_test_data_dir

from ..internal.dsk_container import DskOne


TEST_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')


class TestContainerDSKone(unittest.TestCase):

    def test_init(self):
        test_file = os.path.join(TEST_DATA_DIR, 'test.dsk1')
        test_obj = DskOne(test_file)
        self.assertEqual(test_obj.raw[1:4], b'DSK', 'Raw Data not set correct')
        self.assertEqual(test_obj.header[1], b'DSK1.0', 'header parsing not correct')
        self.assertEqual(test_obj.payload_size, 860293, 'payload length not correct')
        self.assertEqual(get_sha256(test_obj.decoded_payload), '057e936e6c1d45d617fe52decd532776c95c06a1b5e4a8f752d4227a645e5edc', 'payload checksum not correct')

    def test_init_invalid_file(self):
        test_file = os.path.join(get_test_data_dir(), 'container/test.zip')
        test_obj = DskOne(test_file)
        self.assertGreater(len(test_obj.errors), 0, 'errors should be present')

    def tearDown(self):
        gc.collect()

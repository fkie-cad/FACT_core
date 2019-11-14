import gc
import magic
import unittest

from helperFunctions.config import get_config_for_testing
from storage.MongoMgr import MongoMgr
from storage.binary_service import BinaryService
from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_firmware


TEST_FW = create_test_firmware()


class TestBinaryService(unittest.TestCase):

    def setUp(self):
        self.config = get_config_for_testing()
        self.mongo_server = MongoMgr(config=self.config)
        self._init_test_data()
        self.binary_service = BinaryService(config=self.config)

    def _init_test_data(self):
        self.backend_db_interface = BackEndDbInterface(config=self.config)
        self.backend_db_interface.add_firmware(TEST_FW)
        self.backend_db_interface.shutdown()

    def tearDown(self):
        self.mongo_server.shutdown()
        gc.collect()

    def test_get_binary_and_file_name(self):
        binary, file_name = self.binary_service.get_binary_and_file_name(TEST_FW.uid)
        self.assertEqual(file_name, TEST_FW.file_name, 'file_name not correct')
        self.assertEqual(binary, TEST_FW.binary, 'invalid result not correct')

    def test_get_binary_and_file_name_invalid_uid(self):
        binary, file_name = self.binary_service.get_binary_and_file_name('invalid_uid')
        self.assertIsNone(binary, 'should be none')
        self.assertIsNone(file_name, 'should be none')

    def test_get_repacked_binary_and_file_name(self):
        tar, file_name = self.binary_service.get_repacked_binary_and_file_name(TEST_FW.uid)
        self.assertEqual(file_name, '{}.tar.gz'.format(TEST_FW.file_name), 'file_name not correct')
        file_type = magic.from_buffer(tar, mime=True)
        self.assertEqual(file_type, 'application/gzip', 'file type not tar')

    def test_get_repacked_binary_and_file_name_invalid_uid(self):
        binary, file_name = self.binary_service.get_repacked_binary_and_file_name('invalid_uid')
        self.assertIsNone(binary, 'should be none')
        self.assertIsNone(file_name, 'should be none')

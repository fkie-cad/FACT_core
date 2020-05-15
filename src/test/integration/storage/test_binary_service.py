import gc

import magic
import pytest

from storage.binary_service import BinaryService
from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_firmware, get_config_for_testing

TEST_FW = create_test_firmware()


@pytest.mark.usefixtures('start_db')
class TestBinaryService:

    def setup(self):
        self.config = get_config_for_testing()
        self._init_test_data()
        self.binary_service = BinaryService(config=self.config)

    def _init_test_data(self):
        self.backend_db_interface = BackEndDbInterface(config=self.config)
        self.backend_db_interface.add_firmware(TEST_FW)
        self.backend_db_interface.shutdown()

    def teardown(self):
        gc.collect()

    def test_get_binary_and_file_name(self):
        binary, file_name = self.binary_service.get_binary_and_file_name(TEST_FW.uid)
        assert file_name == TEST_FW.file_name, 'file_name not correct'
        assert binary == TEST_FW.binary, 'invalid result not correct'

    def test_get_binary_and_file_name_invalid_uid(self):
        binary, file_name = self.binary_service.get_binary_and_file_name('invalid_uid')
        assert binary is None, 'should be none'
        assert file_name is None, 'should be none'

    def test_get_repacked_binary_and_file_name(self):
        tar, file_name = self.binary_service.get_repacked_binary_and_file_name(TEST_FW.uid)
        assert file_name == '{}.tar.gz'.format(TEST_FW.file_name), 'file_name not correct'

        file_type = magic.from_buffer(tar, mime=False)
        assert 'gzip compressed data' in file_type, 'Result is not an tar.gz file'

    def test_get_repacked_binary_and_file_name_invalid_uid(self):
        binary, file_name = self.binary_service.get_repacked_binary_and_file_name('invalid_uid')
        assert binary is None, 'should be none'
        assert file_name is None, 'should be none'

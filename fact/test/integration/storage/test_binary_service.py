import magic
import pytest

from fact.storage.binary_service import BinaryService
from fact.test.common_helper import create_test_firmware, store_binary_on_file_system

TEST_FW = create_test_firmware()


@pytest.fixture
def binary_service(backend_db, backend_config):
    _init_test_data(backend_config.firmware_file_storage_directory, backend_db)
    return BinaryService()


def _init_test_data(dest_dir, backend_db):
    backend_db.add_object(TEST_FW)
    store_binary_on_file_system(dest_dir, TEST_FW)


def test_get_binary_and_file_name(binary_service):
    binary, file_name = binary_service.get_binary_and_file_name(TEST_FW.uid)
    assert file_name == TEST_FW.file_name, 'file_name not correct'
    assert binary == TEST_FW.binary, 'invalid result not correct'


def test_get_binary_and_file_name_invalid_uid(binary_service):
    binary, file_name = binary_service.get_binary_and_file_name('invalid_uid')
    assert binary is None, 'should be none'
    assert file_name is None, 'should be none'


def test_get_repacked_binary_and_file_name(binary_service):
    tar, file_name = binary_service.get_repacked_binary_and_file_name(TEST_FW.uid)
    assert file_name == f'{TEST_FW.file_name}.tar.gz', 'file_name not correct'

    file_type = magic.from_buffer(tar, mime=False)
    assert 'gzip compressed data' in file_type, 'Result is not an tar.gz file'


def test_get_repacked_binary_and_file_name_invalid_uid(binary_service):
    binary, file_name = binary_service.get_repacked_binary_and_file_name('invalid_uid')
    assert binary is None, 'should be none'
    assert file_name is None, 'should be none'


def test_read_partial_binary(binary_service):
    partial_binary = binary_service.read_partial_binary(TEST_FW.uid, 30, 14)
    assert len(partial_binary) == 14  # noqa: PLR2004
    assert partial_binary == b'get_files_test', 'invalid result not correct'


def test_read_partial_binary_invalid_uid(binary_service):
    result = binary_service.read_partial_binary('invalid_uid', 0, 1337)
    assert result == b'', 'result should be empty'

from pathlib import Path

import pytest
from common_helper_files import get_binary_from_file

from helperFunctions import magic
from objects.file import FileObject
from storage.file_service import FileService
from test.common_helper import TEST_FW, store_binary_on_file_system


@pytest.fixture
def file_service(backend_config):
    store_binary_on_file_system(backend_config.firmware_file_storage_directory, TEST_FW)
    return FileService()


def _check_file_presence_and_content(file_path, file_binary):
    assert Path(file_path).is_file(), 'file exists'
    assert get_binary_from_file(file_path) == file_binary, 'correct content'


def test_generate_path(file_service):
    test_binary = b'abcde'
    file_object = FileObject(test_binary)
    file_path = file_service.generate_path(file_object)
    expected_path = f'{file_service.data_storage_path}/{file_object.uid[:2]}/{file_object.uid}'
    assert file_path == expected_path


def test_store_and_delete_file(file_service):
    test_binary = b'abcde'
    file_object = FileObject(test_binary)

    file_service.store_file(file_object)
    expected_path = f'{file_service.data_storage_path}/{file_object.uid[:2]}/{file_object.uid}'
    _check_file_presence_and_content(expected_path, b'abcde')
    assert file_object.file_path == expected_path, 'wrong file path set in file object'

    file_service.delete_file(file_object.uid)
    assert not Path(file_object.file_path).is_file(), 'file not deleted'


def test_get_file(file_service):
    contents = file_service.get_file(TEST_FW)
    assert contents == TEST_FW.binary, 'invalid result not correct'


def test_get_file_from_uid(file_service):
    contents = file_service.get_file_from_uid(TEST_FW.uid)
    assert contents == TEST_FW.binary, 'invalid result not correct'


def test_get_file_invalid_uid(file_service):
    contents = file_service.get_file_from_uid('invalid_uid')
    assert contents is None, 'should be none'


def test_get_repacked_file(file_service):
    tar = file_service.get_repacked_file(TEST_FW.uid)
    file_type = magic.from_buffer(tar, mime=False)
    assert 'gzip compressed data' in file_type, 'Result is not an tar.gz file'


def test_get_repacked_file_invalid_uid(file_service):
    binary = file_service.get_repacked_file('invalid_uid')
    assert binary is None, 'should be none'


def test_get_partial_file(file_service):
    partial_binary = file_service.get_partial_file(TEST_FW.uid, 30, 14)
    assert len(partial_binary) == 14
    assert partial_binary == b'get_files_test', 'invalid result not correct'


def test_get_partial_file_invalid_uid(file_service):
    result = file_service.get_partial_file('invalid_uid', 0, 1337)
    assert result == b'', 'result should be empty'

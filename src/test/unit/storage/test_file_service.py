from pathlib import Path
from tempfile import TemporaryDirectory

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
    uid = 'abcd_123'
    file_object = FileObject.from_uid(uid, file_name='foo')
    file_path = file_service.generate_path(file_object)
    expected_path = Path(file_service.data_storage_path) / file_object.uid[:2] / file_object.uid
    assert file_path == expected_path


def test_store_and_delete_file(file_service):
    contents = b'abcde'
    uid = 'abcd_123'
    file_object = FileObject.from_uid(uid, file_name='foo')

    file_service.store_file(contents, uid)
    expected_path = Path(file_service.data_storage_path) / file_object.uid[:2] / file_object.uid
    _check_file_presence_and_content(expected_path, contents)
    assert file_object.file_path == expected_path, 'wrong file path set in file object'

    file_service.delete_file(file_object.uid)
    assert not file_object.file_path.is_file(), 'file not deleted'


def test_move_file_to_storage(file_service):
    contents = b'abcde'
    uid = 'abcd_123'
    with TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / 'foobar.bin'
        path.write_bytes(contents)
        file_service.move_file_to_storage(path, uid)
        assert path.is_file() is False, 'file not moved'
        assert file_service.generate_path_from_uid(uid).is_file()


def test_get_file_content(file_service):
    contents = file_service.get_file_content(TEST_FW)
    assert contents == TEST_FW.file_path.read_bytes(), 'invalid result not correct'


def test_get_file_content_from_uid(file_service):
    contents = file_service.get_file_content_from_uid(TEST_FW.uid)
    assert contents == TEST_FW.file_path.read_bytes(), 'invalid result not correct'


def test_get_file_content_invalid_uid(file_service):
    contents = file_service.get_file_content_from_uid('invalid_uid')
    assert contents is None, 'should be none'


def test_get_repacked_file(file_service):
    tar = file_service.get_repacked_file_as_bytes(TEST_FW.uid)
    file_type = magic.from_buffer(tar, mime=False)
    assert 'gzip compressed data' in file_type, 'Result is not an tar.gz file'


def test_get_repacked_file_invalid_uid(file_service):
    binary = file_service.get_repacked_file_as_bytes('invalid_uid')
    assert binary is None, 'should be none'


def test_get_partial_file(file_service):
    partial_binary = file_service.get_partial_file_content(TEST_FW.uid, 30, 14)
    assert len(partial_binary) == 14
    assert partial_binary == b'get_files_test', 'invalid result not correct'


def test_get_partial_file_invalid_uid(file_service):
    result = file_service.get_partial_file_content('invalid_uid', 0, 1337)
    assert result == b'', 'result should be empty'

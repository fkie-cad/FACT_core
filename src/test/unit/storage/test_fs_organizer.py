import os

import pytest
from common_helper_files import get_binary_from_file

from objects.file import FileObject
from storage.fsorganizer import FSOrganizer


@pytest.fixture
def fsorganizer():
    yield FSOrganizer()


def _check_file_presence_and_content(file_path, file_binary):
    assert os.path.exists(file_path), 'file exists'
    assert get_binary_from_file(file_path) == file_binary, 'correct content'


def test_generate_path(fsorganizer):
    test_binary = b'abcde'
    file_object = FileObject(test_binary)
    file_path = fsorganizer.generate_path(file_object)
    # file path should be 'DATA_DIR/UID_PEFIX/UID'
    assert (
        file_path
        == f'{fsorganizer.data_storage_path}/36/36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c_5'
    ), 'generate file path'


def test_store_and_delete_file(fsorganizer):
    test_binary = b'abcde'
    file_object = FileObject(test_binary)

    fsorganizer.store_file(file_object)
    _check_file_presence_and_content(
        f'{fsorganizer.data_storage_path}/36/36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c_5',
        b'abcde',
    )
    assert (
        file_object.file_path
        == f'{fsorganizer.data_storage_path}/36/36bbe50ed96841d10443bcb670d6554f0a34b761be67ec9c4a8ad2c0c44ca42c_5'
    ), 'wrong file path set in file object'

    fsorganizer.delete_file(file_object.uid)
    assert not os.path.exists(file_object.file_path), 'file not deleted'

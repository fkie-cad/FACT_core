# pylint: disable=invalid-name,redefined-outer-name,wrong-import-order
from copy import deepcopy

import pytest

from helperFunctions.object_storage import update_included_files, update_virtual_file_path
from test.common_helper import TEST_TEXT_FILE


@pytest.fixture(scope='function')
def mutable_test_file():
    return deepcopy(TEST_TEXT_FILE)


@pytest.fixture(scope='function')
def mongo_entry():
    return {
        'analysis_tags': {'existing_tag': 'foobar'},
        'files_included': ['legacy_file', 'duplicated_entry'],
        'virtual_file_path': {'any': ['any|virtual|path']}
    }


def test_update_included_files_normal(mutable_test_file, mongo_entry):
    mutable_test_file.files_included = ['i', 'like', 'files']
    files_included = update_included_files(mutable_test_file, mongo_entry)
    assert len(files_included) == 5
    assert all(name in files_included for name in ['i', 'like', 'files', 'legacy_file', 'duplicated_entry'])


def test_update_included_files_duplicate(mutable_test_file, mongo_entry):
    mutable_test_file.files_included = ['beware', 'the', 'duplicated_entry']
    files_included = update_included_files(mutable_test_file, mongo_entry)
    assert len(files_included) == 4
    assert all(name in files_included for name in ['legacy_file', 'beware', 'the', 'duplicated_entry'])


def test_update_virtual_file_path_normal(mutable_test_file, mongo_entry):
    mutable_test_file.virtual_file_path = {'new': ['new|path|in|another|object']}
    virtual_file_path = update_virtual_file_path(mutable_test_file, mongo_entry)
    assert len(virtual_file_path.keys()) == 2
    assert all(root in virtual_file_path for root in ['any', 'new'])


def test_update_virtual_file_path_overwrite(mutable_test_file, mongo_entry):
    mutable_test_file.virtual_file_path = {'any': ['any|virtual|/new/path']}
    virtual_file_path = update_virtual_file_path(mutable_test_file, mongo_entry)
    assert len(virtual_file_path.keys()) == 1
    assert virtual_file_path['any'] == ['any|virtual|/new/path']


def test_update_vfp_new_archive_in_old_object(mutable_test_file, mongo_entry):
    mutable_test_file.virtual_file_path = {'any': ['any|virtual|new_archive|additional_path']}
    virtual_file_path = update_virtual_file_path(mutable_test_file, mongo_entry)
    assert len(virtual_file_path.keys()) == 1
    assert sorted(virtual_file_path['any']) == ['any|virtual|new_archive|additional_path', 'any|virtual|path']

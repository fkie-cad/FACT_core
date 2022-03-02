# pylint: disable=invalid-name,redefined-outer-name,wrong-import-order
from copy import deepcopy

import pytest

from helperFunctions.object_storage import update_included_files
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

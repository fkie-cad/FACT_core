from copy import deepcopy

import pytest

from helperFunctions.object_storage import update_analysis_tags, update_included_files, update_virtual_file_path
from test.common_helper import TEST_TEXT_FILE


@pytest.fixture(scope='function')
def mutable_test_file():
    return deepcopy(TEST_TEXT_FILE)


@pytest.fixture(scope='function')
def mongo_entry():
    return {
        'analysis_tags': {'existing_tag': 'foobar'},
        'files_included': ['legacy_file', 'duplicated_entry'],
        'virtual_file_path': {'any': 'any|virtual|path'}
    }


def test_update_analysis_tags_normal(mutable_test_file, mongo_entry):
    mutable_test_file.analysis_tags = {'new_tag': 'hurray'}
    analysis_tags = update_analysis_tags(mutable_test_file, mongo_entry)
    assert all(key in analysis_tags for key in ['existing_tag', 'new_tag']), 'not both tags found'
    assert len(analysis_tags.keys()) == 2, 'unaccounted tag'


def test_update_analysis_tags_overwrite(mutable_test_file, mongo_entry):
    mutable_test_file.analysis_tags = {'new_tag': 'hurray', 'existing_tag': 'overwrite'}
    analysis_tags = update_analysis_tags(mutable_test_file, mongo_entry)
    assert len(analysis_tags.keys()) == 2, 'unaccounted tag'
    assert analysis_tags['existing_tag'] == 'overwrite'


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
    mutable_test_file.virtual_file_path = {'new': 'new|path|in|another|object'}
    virtual_file_path = update_virtual_file_path(mutable_test_file, mongo_entry)
    assert len(virtual_file_path.keys()) == 2
    assert all(root in virtual_file_path for root in ['any', 'new'])


def test_update_virtual_file_path_overwrite(mutable_test_file, mongo_entry):
    mutable_test_file.virtual_file_path = {'any': 'new|path|from|better|unpacker'}
    virtual_file_path = update_virtual_file_path(mutable_test_file, mongo_entry)
    assert len(virtual_file_path.keys()) == 1
    assert virtual_file_path['any'] == 'new|path|from|better|unpacker'

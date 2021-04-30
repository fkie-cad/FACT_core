# pylint: disable=redefined-outer-name
from copy import deepcopy
from unittest.mock import patch

import pytest

from helperFunctions.tag import _check_tag_integrity, add_tags_to_object, check_tags, update_tags
from test.common_helper import TEST_TEXT_FILE


@pytest.fixture(scope='function')
def test_object():
    return deepcopy(TEST_TEXT_FILE)


@pytest.mark.parametrize('tag, message', [
    (dict(), 'missing key'),
    ({'value': None, 'color': 'danger', 'propagate': True}, 'tag value has to be a string'),
    ({'value': 12, 'color': 'danger', 'propagate': True}, 'tag value has to be a string'),
    ({'value': 'good', 'color': None, 'propagate': True}, 'bad tag color'),
    ({'value': 'good', 'color': 12, 'propagate': True}, 'bad tag color'),
    ({'value': 'good', 'color': 'bad color', 'propagate': True}, 'bad tag color'),
    ({'value': 'good', 'color': 'danger', 'propagate': None}, 'tag propagate key has to be a boolean'),
    ({'value': 'good', 'color': 'danger', 'propagate': 12}, 'tag propagate key has to be a boolean'),
])
def test_check_tag_integrity_bad(tag, message):
    with pytest.raises(ValueError) as exec_info:
        _check_tag_integrity(tag)
    assert message in str(exec_info.value)


def test_check_tag_integrity_good():
    tag = {'value': 'good', 'color': 'danger', 'propagate': False}
    assert _check_tag_integrity(tag) is None


def test_add_tags_to_object_unknown_analysis(test_object):  # pylint: disable=invalid-name
    file_object = add_tags_to_object(test_object, 'any_analysis')
    assert not file_object.analysis_tags


def test_add_tags_to_object_success(test_object):
    test_object.processed_analysis['some_analysis'] = {'tags': {'tag': 'any_tag'}}
    file_object = add_tags_to_object(test_object, 'some_analysis')
    assert 'some_analysis' in file_object.analysis_tags
    assert file_object.analysis_tags['some_analysis'] == {'tag': 'any_tag'}


def test_check_tags_no_analysis():
    result = check_tags(TEST_TEXT_FILE, 'non_existing_analysis')
    assert result['notags']


def test_check_tags_no_tags():
    result = check_tags(TEST_TEXT_FILE, 'dummy')
    assert result['notags']


@patch.object(TEST_TEXT_FILE, 'processed_analysis', {'mock_plugin': {'tags': {'some_stuff': 'anything'}}})
def test_check_tags_missing_root_uid():
    result = check_tags(TEST_TEXT_FILE, 'mock_plugin')
    assert result['notags']


@patch.object(TEST_TEXT_FILE, 'processed_analysis', {'mock_plugin': {'tags': None}})
def test_check_tags_bad_type():
    result = check_tags(TEST_TEXT_FILE, 'mock_plugin')
    assert result['notags']


@patch.object(TEST_TEXT_FILE, 'processed_analysis', {'mock_plugin': {'tags': {'some_stuff': 'anything', 'root_uid': 'abc_123'}}})
def test_check_tags_found():
    result = check_tags(TEST_TEXT_FILE, 'mock_plugin')
    assert not result['notags']
    assert result['tags'] == {'some_stuff': 'anything'}


def test_update_tags_propagate_exception():  # pylint: disable=invalid-name
    bad_tag = {'value': 'good', 'color': 'bad color', 'propagate': True}
    with pytest.raises(ValueError):
        update_tags(dict(), 'some_plugin', 'any_tag', bad_tag)


def test_update_tags_new_plugin():
    tag = {'value': 'good', 'color': 'danger', 'propagate': False}
    result = update_tags(old_tags=dict(), plugin_name='some_plugin', tag_name='any_tag', tag=tag)
    assert result['some_plugin']['any_tag'] == tag


def test_update_tags_overwrite_tag():
    tag = {'value': 'good', 'color': 'danger', 'propagate': False}
    result = update_tags(old_tags=dict(some_plugin=dict(any_tag=dict())), plugin_name='some_plugin', tag_name='any_tag', tag=tag)
    assert result['some_plugin']['any_tag'] == tag

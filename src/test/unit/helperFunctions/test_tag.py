from copy import deepcopy
from unittest.mock import patch

import pytest

from helperFunctions.tag import add_tags_to_object, check_tag_integrity, check_tags, update_tags
from test.common_helper import TEST_TEXT_FILE


@pytest.fixture(scope='function')
def test_object():
    return deepcopy(TEST_TEXT_FILE)


@pytest.mark.parametrize('tag', [
    dict(),
    {'value': None, 'color': 'danger', 'propagate': True},
    {'value': 12, 'color': 'danger', 'propagate': True},
    {'value': 'good', 'color': None, 'propagate': True},
    {'value': 'good', 'color': 12, 'propagate': True},
    {'value': 'good', 'color': 'bad color', 'propagate': True},
    {'value': 'good', 'color': 'danger', 'propagate': None},
    {'value': 'good', 'color': 'danger', 'propagate': 12},
])
def test_check_tag_integrity_bad(tag):
    status, _ = check_tag_integrity(tag)
    assert status is False


def test_check_tag_integrity_good():
    tag = {'value': 'good', 'color': 'danger', 'propagate': False}
    status, _ = check_tag_integrity(tag)
    assert status is True


def test_add_tags_to_object_unkown_analysis(test_object):  # pylint: disable=redefined-outer-name,invalid-name
    file_object = add_tags_to_object(test_object, 'any_analysis')
    assert not file_object.analysis_tags


def test_add_tags_to_object_success(test_object):  # pylint: disable=redefined-outer-name
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

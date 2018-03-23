import pytest

from helperFunctions.tag import TagColor, check_tags, add_tags_to_object, update_tags, check_tag_integrity
from test.common_helper import TEST_TEXT_FILE


@pytest.fixture(scope='function')
def test_object():
    return TEST_TEXT_FILE


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
    status, message = check_tag_integrity(tag)
    assert status is False


def test_check_tag_integrity_good():
    tag = {'value': 'good', 'color': 'danger', 'propagate': False}
    status, message = check_tag_integrity(tag)
    assert status is True


def test_add_tags_to_object_unkown_analysis(test_object):
    file_object = add_tags_to_object(test_object, 'any_analysis')
    assert not file_object.analysis_tags


def test_add_tags_to_object_success(test_object):
    test_object.processed_analysis['some_analysis'] = {'tags': {'tag': 'any_tag'}}
    file_object = add_tags_to_object(test_object, 'some_analysis')
    assert 'some_analysis' in file_object.analysis_tags
    assert file_object.analysis_tags['some_analysis'] == {'tag': 'any_tag'}

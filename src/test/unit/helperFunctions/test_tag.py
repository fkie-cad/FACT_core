# pylint: disable=redefined-outer-name

import pytest

from helperFunctions.tag import update_tags


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

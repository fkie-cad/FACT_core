# pylint: disable=redefined-outer-name,wrong-import-order

from unittest import mock

import pytest

from test.common_helper import get_config_for_testing
from web_interface.filter import list_group_collapse, render_analysis_tags, render_fw_tags
from web_interface.frontend_main import WebFrontEnd


@pytest.fixture()
def frontend():
    return WebFrontEnd(get_config_for_testing())


@mock.patch('intercom.front_end_binding.InterComFrontEndBinding', lambda **_: None)
def test_list_group_collapse(frontend):
    with frontend.app.app_context():
        collapsed_list_group = list_group_collapse(['a', 'b'])

    assert 'data-toggle="collapse"' in collapsed_list_group
    assert '<span>a</span>' in collapsed_list_group
    assert '<span class="btn btn-sm btn-primary">1</span>' in collapsed_list_group
    assert '<div class="list-group-item border-top">b</div>' in collapsed_list_group


@pytest.mark.parametrize(
    'tag_dict, output',
    [
        ({
            'a': 'danger'
        }, '<span class="badge badge-danger mr-2" style="font-size: 14px;" > a</span>'),
        (
            {
                'a': 'danger', 'b': 'primary'
            },
            '<span class="badge badge-danger mr-2" style="font-size: 14px;" > a</span>'
            '<span class="badge badge-primary mr-2" style="font-size: 14px;" > b</span>'
        ), (None, '')
    ]
)
def test_render_fw_tags(frontend, tag_dict, output):
    with frontend.app.app_context():
        assert render_fw_tags(tag_dict).replace('\n', '').replace('    ', ' ') == output


def test_empty_analysis_tags():
    assert render_analysis_tags({}) == ''


def test_render_analysis_tags_success(frontend):
    tags = {'such plugin': {'tag': {'color': 'success', 'value': 'wow'}}}
    with frontend.app.app_context():
        output = render_analysis_tags(tags).replace('\n', '').replace('    ', ' ')
    assert 'badge-success' in output
    assert '> wow<' in output


def test_render_analysis_tags_fix(frontend):
    tags = {'such plugin': {'tag': {'color': 'very color', 'value': 'wow'}}}
    with frontend.app.app_context():
        output = render_analysis_tags(tags).replace('\n', '').replace('    ', ' ')
    assert 'badge-primary' in output
    assert '> wow<' in output


def test_render_analysis_tags_bad_type():
    tags = {'such plugin': {42: {'color': 'very color', 'value': 'wow'}}}
    with pytest.raises(AttributeError):
        render_analysis_tags(tags)

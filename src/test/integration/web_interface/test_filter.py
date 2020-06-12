from test.common_helper import get_config_for_testing
from web_interface.filter import list_group_collapse
from web_interface.frontend_main import WebFrontEnd


def test_list_group_collapse():
    with WebFrontEnd(get_config_for_testing()).app.app_context():
        collapsed_list_group = list_group_collapse(['a', 'b'])

    assert 'data-toggle="collapse"' in collapsed_list_group
    assert '<span>a</span>' in collapsed_list_group
    assert '<span class="btn btn-sm btn-primary">1</span>' in collapsed_list_group
    assert '<div class="list-group-item border-top">b</div>' in collapsed_list_group

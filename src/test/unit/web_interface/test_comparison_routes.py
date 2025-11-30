import pytest

from test.common_helper import CommonDatabaseMock
from web_interface.components.comparison_routes import (
    ComparisonRoutes,
    _add_plugin_views_to_comparison_view,
    _get_comparison_view,
    _insert_plugin_into_view_at_index,
)


class TemplateDbMock(CommonDatabaseMock):
    @staticmethod
    def get_view(name):
        if name == 'plugin_1':
            return b'<plugin 1 view>'
        return None


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=TemplateDbMock)
def test_get_comparison_plugin_views(web_frontend):
    comparison_result = {'plugins': {}}
    result = ComparisonRoutes._get_comparison_plugin_views(web_frontend, comparison_result)
    assert result == ([], [])

    comparison_result = {'plugins': {'plugin_1': None, 'plugin_2': None}}
    plugin_views, plugins_without_view = ComparisonRoutes._get_comparison_plugin_views(web_frontend, comparison_result)
    assert plugin_views == [('plugin_1', b'<plugin 1 view>')]
    assert plugins_without_view == ['plugin_2']


def test_get_comparison_view():
    result = _get_comparison_view([])
    assert '>General information<' in result
    assert '--- plugin results ---' in result


def test_add_views_missing_key():
    plugin_views = [('plugin_1', b'<plugin view 1>'), ('plugin_2', b'<plugin view 2>')]
    comparison_view = 'xxxxxyyyyy'
    result = _add_plugin_views_to_comparison_view(comparison_view, plugin_views)
    assert result == comparison_view


def test_add_plugin_views():
    plugin_views = [('plugin_1', b'<plugin view 1>'), ('plugin_2', b'<plugin view 2>')]
    key = '{# individual plugin views #}'
    comparison_view = f'xxxxx{key}yyyyy'
    key_index = comparison_view.find(key)
    result = _add_plugin_views_to_comparison_view(comparison_view, plugin_views)

    for plugin, view in plugin_views:
        assert f"elif plugin == '{plugin}'" in result
        assert view.decode() in result
        assert key_index + len(key) <= result.find(view.decode()) < result.find('yyyyy')


def test_insert_plugin_into_view():
    view = '------><------'
    plugin = 'o'
    index = view.find('<')

    assert _insert_plugin_into_view_at_index(plugin, view, 0) == 'o------><------'
    assert _insert_plugin_into_view_at_index(plugin, view, index) == '------>o<------'
    assert _insert_plugin_into_view_at_index(plugin, view, len(view) + 10) == '------><------o'
    assert _insert_plugin_into_view_at_index(plugin, view, -10) == view

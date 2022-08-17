# pylint: disable=protected-access

from test.common_helper import CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest
from web_interface.components.compare_routes import (
    CompareRoutes, _add_plugin_views_to_compare_view, _get_compare_view, _insert_plugin_into_view_at_index,
)


class TemplateDbMock(CommonDatabaseMock):
    @staticmethod
    def get_view(name):
        if name == 'plugin_1':
            return b'<plugin 1 view>'
        return None


class TestAppComparisonBasket(WebInterfaceTest):
    def setup_class(self, *_, **__):
        super().setup_class(db_mock=TemplateDbMock)

    def test_get_compare_plugin_views(self):
        compare_result = {'plugins': {}}
        result = CompareRoutes._get_compare_plugin_views(self.frontend, compare_result)
        assert result == ([], [])

        compare_result = {'plugins': {'plugin_1': None, 'plugin_2': None}}
        plugin_views, plugins_without_view = CompareRoutes._get_compare_plugin_views(self.frontend, compare_result)
        assert plugin_views == [('plugin_1', b'<plugin 1 view>')]
        assert plugins_without_view == ['plugin_2']


def test_get_compare_view():
    result = _get_compare_view([])
    assert '>General information<' in result
    assert '--- plugin results ---' in result


def test_add_views_missing_key():
    plugin_views = [('plugin_1', b'<plugin view 1>'), ('plugin_2', b'<plugin view 2>')]
    compare_view = 'xxxxxyyyyy'
    result = _add_plugin_views_to_compare_view(compare_view, plugin_views)
    assert result == compare_view


def test_add_plugin_views():
    plugin_views = [('plugin_1', b'<plugin view 1>'), ('plugin_2', b'<plugin view 2>')]
    key = '{# individual plugin views #}'
    compare_view = f'xxxxx{key}yyyyy'
    key_index = compare_view.find(key)
    result = _add_plugin_views_to_compare_view(compare_view, plugin_views)

    for plugin, view in plugin_views:
        assert 'elif plugin == \'{}\''.format(plugin) in result
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

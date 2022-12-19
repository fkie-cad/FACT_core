import unittest

from helperFunctions.plugin import _get_plugin_src_dirs, import_plugins

TEST_PLUGINS_BASE_PATH = 'test/data/plugin_system'


class TestHelperFunctionsPlugin(unittest.TestCase):
    def test_get_plugin_src_dirs(self):
        result = _get_plugin_src_dirs(TEST_PLUGINS_BASE_PATH)
        assert isinstance(result, list), 'result is not a list'
        assert 'plugin_one' in sorted(result)[0], 'plugin not found'
        assert len(result) == 2, 'number of found plugin directories not correct'

    def test_load_plugins(self):
        result = import_plugins('plugins.test', TEST_PLUGINS_BASE_PATH)
        imported_plugins = result.list_plugins()
        assert len(imported_plugins) == 1, 'worng number of plugins imported'
        assert imported_plugins[0] == 'plugin_one', 'plugin name not correct'

from helperFunctions.fileSystem import get_src_dir
from helperFunctions.plugin import discover_analysis_plugins

TEST_PLUGINS_SRC_DIR = f'{get_src_dir()}/test/data/plugin_system'


def test_import_plugins(monkeypatch):
    monkeypatch.setattr('helperFunctions.plugin.get_src_dir', lambda: TEST_PLUGINS_SRC_DIR)

    plugins = discover_analysis_plugins()
    assert len(plugins) == 1, 'wrong number of plugins imported'
    assert plugins[0].__name__ == 'plugins.analysis.plugin_one.code.plugin_one', 'plugin name not correct'

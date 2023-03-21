from helperFunctions.fileSystem import get_src_dir
from helperFunctions.plugin import discover_analysis_plugins

TEST_PLUGINS_SRC_DIR = f'{get_src_dir()}/test/data/plugin_system'


def test_import_plugins(monkeypatch):
    monkeypatch.setattr('helperFunctions.plugin.get_src_dir', lambda: TEST_PLUGINS_SRC_DIR)

    plugins = sorted(discover_analysis_plugins(), key=lambda k: k.__name__)
    # "plugin_one" and "crashes_during_instantiation"
    assert len(plugins) == 2, 'wrong number of plugins imported'
    assert plugins[1].__name__ == 'plugins.analysis.plugin_one.code.plugin_one', 'plugin name not correct'

import logging
from importlib import import_module
from pathlib import Path

from common_helper_files import get_dirs_in_dir
from pluginbase import PluginBase

from helperFunctions.fileSystem import get_src_dir

ANALYSIS_DIR = Path(__file__).parent.parent / 'plugins' / 'analysis'


def extract_plugin_code(dir_path):
    for item in dir_path.iterdir():
        if item.is_file() and not item.name == '__init__.py':
            return item
    return None


def import_all():
    plugins = list()
    for plugin in ANALYSIS_DIR.iterdir():
        if not plugin.name.startswith('.') and not plugin.name.startswith('_'):
            import_path = str(extract_plugin_code(Path(plugin, 'code').relative_to(Path(__file__).parent.parent)))[:-3].replace('/', '.')
            plugins.append(import_module(import_path))
    return plugins


def import_plugins(plugin_mount, plugin_base_dir):
    plugin_base = PluginBase(package=plugin_mount)
    plugin_src_dirs = _get_plugin_src_dirs(plugin_base_dir)
    return plugin_base.make_plugin_source(searchpath=plugin_src_dirs)


def _get_plugin_src_dirs(base_dir):
    plug_in_base_path = Path(get_src_dir(), base_dir)
    plugin_dirs = get_dirs_in_dir(str(plug_in_base_path))
    plugins = []
    for plugin_path in plugin_dirs:
        plugin_code_dir = Path(plugin_path, 'code')
        if plugin_code_dir.is_dir():
            plugins.append(str(plugin_code_dir))
        else:
            logging.warning('Plugin has no code directory: {}'.format(plugin_path))
    return plugins

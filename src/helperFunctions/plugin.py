import logging
from pathlib import Path
from typing import List

from common_helper_files import get_dirs_in_dir
from pluginbase import PluginBase

from helperFunctions.fileSystem import get_src_dir


def import_plugins(plugin_mount, plugin_base_dir):
    '''
    Imports all plugins in plugin_base_dir with packagename plugin_mount

    :param plugin_mount: The packagename that the plugins will reside in
    :param plugin_base_dir: The directory that contains the plugins
    :return: A pluginbase.PluginSource containing all plugins from plugin_base_dir
    '''
    plugin_base = PluginBase(package=plugin_mount)
    plugin_src_dirs = _get_plugin_src_dirs(plugin_base_dir)
    return plugin_base.make_plugin_source(searchpath=plugin_src_dirs)


def _get_plugin_src_dirs(base_dir: str) -> List[str]:
    '''
    Returns a list of all plugin code directories.
    E.g. if base_dir contains the qemu_exec plugin it would return
    `base_dir`/qemu_exec/code.

    :param base_dir: The root directory of all plugins
    '''
    plug_in_base_path = Path(get_src_dir(), base_dir)
    plugin_dirs = get_dirs_in_dir(str(plug_in_base_path))
    plugins = []
    for plugin_path in plugin_dirs:
        if plugin_path.endswith('__pycache__'):
            continue
        plugin_code_dir = Path(plugin_path, 'code')
        if plugin_code_dir.is_dir():
            plugins.append(str(plugin_code_dir))
        else:
            logging.warning(f'Plugin has no code directory: {plugin_path}')
    return plugins

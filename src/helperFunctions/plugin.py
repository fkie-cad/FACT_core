from common_helper_files.fail_safe_file_operations import get_dirs_in_dir
import os
from pluginbase import PluginBase

from helperFunctions.fileSystem import get_src_dir


def import_plugins(plugin_mount, plugin_base_dir):
    plugin_base = PluginBase(package=plugin_mount)
    plugin_src_dirs = _get_plugin_src_dirs(plugin_base_dir)
    return plugin_base.make_plugin_source(searchpath=plugin_src_dirs)


def _get_plugin_src_dirs(base_dir):
    plugin_dirs = get_dirs_in_dir(os.path.join(get_src_dir(), base_dir))
    return [os.path.join(x, "code") for x in plugin_dirs]

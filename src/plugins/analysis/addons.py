import io

import yara

from helperFunctions.fileSystem import get_src_dir
from plugins import analysis


class Yara:
    """A convinience class for using yara within :py:class:`PluginV0`"""

    def __init__(self, plugin: analysis.PluginV0):
        """Sets system_version.
        Raises an FileNotFoundError if the singatures are not compiled.
        """
        assert plugin.metadata.system_version is None, 'YaraAddon would overwrite system_version'
        plugin.metadata.system_version = yara.__version__

        rules_path = f'{get_src_dir()}/analysis/signatures/{plugin.metadata.name}.yc'
        self._rules = yara.load(rules_path)

    def match(self, file_handle: io.FileIO) -> list[yara.Match]:
        """A convinience method to call ``yaml.Rules.match`` for the rules of the plugin.

        The file handle is NOT read.
        """
        return self._rules.match(file_handle.name)

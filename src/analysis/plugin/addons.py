from __future__ import annotations

from typing import TYPE_CHECKING

import yara

from helperFunctions.fileSystem import get_src_dir

if TYPE_CHECKING:
    import io

    from analysis.plugin import AnalysisPluginV0


class Yara:
    """A convenience class for using yara within :py:class:`AnalysisPluginV0`"""

    def __init__(self, plugin: AnalysisPluginV0):
        """Sets system_version.
        Raises an FileNotFoundError if the signatures are not compiled.
        """
        if plugin.metadata.system_version is not None:
            raise RuntimeError('YaraAddon would overwrite system_version')
        plugin.metadata.system_version = yara.__version__

        rules_path = f'{get_src_dir()}/analysis/signatures/{plugin.metadata.name}.yc'
        self._rules = yara.load(rules_path)

    def match(self, file_handle: io.FileIO) -> list[yara.Match]:
        """A convenience method to call ``yara.Rules.match`` for the rules of the plugin.

        The file handle is NOT read.
        """
        return self._rules.match(file_handle.name)

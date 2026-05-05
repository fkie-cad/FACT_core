from __future__ import annotations

from typing import TYPE_CHECKING, cast

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

        self._rules_path = f'{get_src_dir()}/analysis/signatures/{plugin.metadata.name}.yc'
        self._rules: yara.Rules | None = None  # lazy loaded during first access

    @property
    def rules(self) -> yara.Rules:
        if self._rules is None:
            self._rules = yara.load(self._rules_path)
        return self._rules

    def __getstate__(self):
        state = self.__dict__.copy()
        del state['_rules']  # cannot be pickled
        return state

    def match(self, file_handle: io.FileIO) -> list[yara.Match]:
        """A convenience method to call ``yara.Rules.match`` for the rules of the plugin.

        The file handle is NOT read.
        """
        return self.rules.match(file_handle.name)

from __future__ import annotations  # noqa: N999

from abc import abstractmethod

from plugins.base import BasePlugin
from typing import TYPE_CHECKING, Iterable


if TYPE_CHECKING:
    from storage.db_interface_comparison import ComparisonDbInterface
    from objects.file import FileObject


class CompareBasePlugin(BasePlugin):
    """
    This is the compare plug-in base class. All compare plug-ins should be derived from this class.
    """

    def __init__(self, db_interface: ComparisonDbInterface, **kwargs):
        super().__init__(plugin_path=self.FILE, **kwargs)
        self.database = db_interface

    @abstractmethod
    def compare_function(self, fo_list: list[FileObject]) -> dict:
        """
        This function must be implemented by the plug-in.
        'fo_list' is a list with file_objects including analysis and all summaries
        this function should return a dictionary
        """
        return {'dummy': {'all': 'dummy-content', 'collapse': False}}

    def compare(self, fo_list: list[FileObject]) -> dict:
        """
        This function is called by the compare module.
        """
        missing_deps = _get_unmatched_dependencies(fo_list, self.DEPENDENCIES)
        if len(missing_deps) > 0:
            return {'Compare Skipped': {'all': f"Required analysis not present: {', '.join(missing_deps)}"}}
        return self.compare_function(fo_list)


def _get_unmatched_dependencies(fo_list: list[FileObject], dependency_list: Iterable[str]) -> set[str]:
    return {dependency for dependency in dependency_list for fo in fo_list if dependency not in fo.processed_analysis}

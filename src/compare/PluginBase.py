from __future__ import annotations  # noqa: N999

from abc import abstractmethod
from typing import TYPE_CHECKING

from plugins.base import BasePlugin

if TYPE_CHECKING:
    from objects.file import FileObject


class CompareBasePlugin(BasePlugin):
    """
    This is the compare plug-in base class. All compare plug-ins should be derived from this class.
    """

    # must be set by the plugin:
    FILE = None
    # a tuple of comparison plugin names on whose results this plugin depends
    # (and which therefore must run before the plugin)
    COMPARISON_DEPS: tuple[str, ...] = ()

    def __init__(self, config=None, db_interface=None, view_updater=None):
        super().__init__(plugin_path=self.FILE, view_updater=view_updater)
        self.config = config
        self.database = db_interface

    @abstractmethod
    def compare_function(self, fo_list: list[FileObject], dependency_results: dict[str, dict]) -> dict[str, dict]:
        """
        This function must be implemented by the plugin.
        `fo_list` is a list with file_objects including analysis and all summaries.
        `dependency_results` is a dict that contains the results of the dependencies listed in `COMPARISON_DEPS`
        (key: dependency plugin name, value: its result dict).
        This function should return a dictionary.
        """
        return {'dummy': {'all': 'dummy-content', 'collapse': False}}

    def compare(self, fo_list: list[FileObject], dependency_results: dict[str, dict]) -> dict[str, dict]:
        """
        This function is called by the compare module.
        """
        missing_comparison_deps = self._get_missing_comparison_deps(dependency_results)
        if missing_comparison_deps:
            return {
                'Comparison Skipped': {
                    'all': f"Required comparison results are missing: {', '.join(missing_comparison_deps)}",
                }
            }
        missing_analysis_deps = self._get_missing_analysis_deps(fo_list)
        if missing_analysis_deps:
            return {'Compare Skipped': {'all': f"Required analyses not present: {', '.join(missing_analysis_deps)}"}}
        return self.compare_function(fo_list, dependency_results)

    def _get_missing_comparison_deps(self, dependency_results: dict[str, dict]) -> list[str]:
        return [
            dependency
            for dependency in self.COMPARISON_DEPS
            if dependency not in dependency_results or _dependency_was_skipped(dependency, dependency_results)
        ]

    def _get_missing_analysis_deps(self, fo_list: list[FileObject]) -> set[str]:
        return {dep for dep in self.DEPENDENCIES for fo in fo_list if dep not in fo.processed_analysis}


def _dependency_was_skipped(dependency: str, dependency_results: dict[str, dict]) -> bool:
    return any('skipped' in k.lower() for k in dependency_results.get(dependency, {}))

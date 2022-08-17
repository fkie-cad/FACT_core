import logging
from copy import copy
from time import time
from typing import List, Set, Union

from helperFunctions.merge_generators import shuffled
from objects.file import FileObject
from objects.firmware import Firmware

MANDATORY_PLUGINS = ['file_type', 'file_hashes']


class AnalysisTaskScheduler:
    def __init__(self, plugins):
        self.plugins = plugins

    def schedule_analysis_tasks(self, fo, scheduled_analysis, mandatory=False):
        scheduled_analysis = self._add_dependencies_recursively(copy(scheduled_analysis) or [])
        fo.scheduled_analysis = self._smart_shuffle(
            scheduled_analysis + MANDATORY_PLUGINS if mandatory else scheduled_analysis
        )

    def _smart_shuffle(self, plugin_list: List[str]) -> List[str]:
        scheduled_plugins = []
        remaining_plugins = set(plugin_list)

        while remaining_plugins:
            next_plugins = self._get_plugins_with_met_dependencies(remaining_plugins, scheduled_plugins)
            if not next_plugins:
                logging.error(
                    f'Error: Could not schedule plugins because dependencies cannot be fulfilled: {remaining_plugins}'
                )
                break
            scheduled_plugins[:0] = shuffled(next_plugins)
            remaining_plugins.difference_update(next_plugins)

        # assure file type is first for blacklist functionality
        if 'file_type' in scheduled_plugins and scheduled_plugins[-1] != 'file_type':
            scheduled_plugins.remove('file_type')
            scheduled_plugins.append('file_type')
        return scheduled_plugins

    def _get_plugins_with_met_dependencies(self, remaining_plugins: Set[str],
                                           scheduled_plugins: List[str]) -> List[str]:
        met_dependencies = scheduled_plugins
        return [
            plugin for plugin in remaining_plugins
            if all(dependency in met_dependencies for dependency in self.plugins[plugin].DEPENDENCIES)
        ]

    def _add_dependencies_recursively(self, scheduled_analyses: List[str]) -> List[str]:
        scheduled_analyses_set = set(scheduled_analyses)
        while True:
            new_dependencies = self.get_cumulative_remaining_dependencies(scheduled_analyses_set)
            if not new_dependencies:
                break
            scheduled_analyses_set.update(new_dependencies)
        return list(scheduled_analyses_set)

    def get_cumulative_remaining_dependencies(self, scheduled_analyses: Set[str]) -> Set[str]:
        return {dependency
                for plugin in scheduled_analyses
                for dependency in self.plugins[plugin].DEPENDENCIES}.difference(scheduled_analyses)

    def reschedule_failed_analysis_task(self, fw_object: Union[Firmware, FileObject]):
        failed_plugin, cause = fw_object.analysis_exception
        fw_object.processed_analysis[failed_plugin] = self._get_failed_analysis_result(cause, failed_plugin)
        for plugin in fw_object.scheduled_analysis[:]:
            if failed_plugin in self.plugins[plugin].DEPENDENCIES:
                fw_object.scheduled_analysis.remove(plugin)
                logging.warning(
                    f'Unscheduled analysis {plugin} for {fw_object.uid} because dependency {failed_plugin} failed'
                )
                fw_object.processed_analysis[plugin] = self._get_failed_analysis_result(
                    f'Analysis of dependency {failed_plugin} failed', plugin
                )
        fw_object.analysis_exception = None

    def _get_failed_analysis_result(self, cause: str, plugin: str) -> dict:
        return {
            'failed': cause,
            'plugin_version': self.plugins[plugin].VERSION,
            'analysis_date': time(),
        }

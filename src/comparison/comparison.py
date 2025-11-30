from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from helperFunctions.plugin import discover_comparison_plugins
from helperFunctions.virtual_file_path import get_paths_for_all_parents
from objects.firmware import Firmware
from storage.binary_service import BinaryService

if TYPE_CHECKING:
    from comparison.comparison_base_plugin import ComparisonBasePlugin
    from objects.file import FileObject
    from storage.db_interface_comparison import ComparisonDbInterface


class Comparison:
    """
    This Module compares firmware images
    """

    comparison_plugins = {}  # noqa: RUF012

    def __init__(self, db_interface: ComparisonDbInterface | None = None):
        self.db_interface = db_interface
        self._setup_plugins()
        logging.info(f'Comparison plugins available: {", ".join(self.comparison_plugins)}')

    def compare(self, uid_list):
        logging.info(f'Comparison in progress: {uid_list}')
        binary_service = BinaryService()

        fo_list = []
        for uid in uid_list:
            fo = self.db_interface.get_complete_object_including_all_summaries(uid)
            fo.binary = binary_service.get_binary_and_file_name(fo.uid)[0]
            fo_list.append(fo)

        return self.compare_objects(fo_list)

    def compare_objects(self, fo_list):
        return {
            'general': self._create_general_section_dict(fo_list),
            'plugins': self._execute_comparison_plugins(fo_list),
        }

    def _create_general_section_dict(self, object_list):
        general = {}
        vfp_data = self._get_vfp_data(object_list)
        for fo in object_list:
            if isinstance(fo, Firmware):
                fo.root_uid = fo.uid
                general.setdefault('device_name', {})[fo.uid] = fo.device_name
                general.setdefault('device_part', {})[fo.uid] = fo.part
                general.setdefault('device_class', {})[fo.uid] = fo.device_class
                general.setdefault('vendor', {})[fo.uid] = fo.vendor
                general.setdefault('version', {})[fo.uid] = fo.version
                general.setdefault('release_date', {})[fo.uid] = fo.release_date
            else:
                general.setdefault('firmwares_including_this_file', {})[fo.uid] = list(fo.parent_firmware_uids)
            general.setdefault('hid', {})[fo.uid] = fo.get_hid()
            general.setdefault('size', {})[fo.uid] = fo.size
            general.setdefault('virtual_file_path', {})[fo.uid] = vfp_data[fo.uid]
            general.setdefault('number_of_files', {})[fo.uid] = len(fo.list_of_all_included_files)
        return general

    def _get_vfp_data(self, object_list: list[FileObject]) -> dict[str, list[str]]:
        vfp_data = {
            uid: get_paths_for_all_parents(vfp_dict)
            for uid, vfp_dict in self.db_interface.get_vfps_for_uid_list([fo.uid for fo in object_list]).items()
        }
        # firmware objects don't have "virtual file paths" (because they are themselves not included in another file)
        for fo in object_list:
            if isinstance(fo, Firmware):
                vfp_data[fo.uid] = [fo.file_name]
        return vfp_data

    # --- plug-in system ---

    def _setup_plugins(self):
        self.comparison_plugins = {}
        self._init_plugins()

    def _init_plugins(self):
        for plugin in discover_comparison_plugins():
            try:
                self.comparison_plugins[plugin.ComparisonPlugin.NAME] = plugin.ComparisonPlugin(
                    db_interface=self.db_interface
                )
            except Exception:
                logging.error(f'Could not import comparison plugin {plugin.AnalysisPlugin.NAME}', exc_info=True)

    def _execute_comparison_plugins(self, fo_list: list[FileObject]) -> dict[str, dict]:
        comparison_results = {}
        for plugin in schedule_comparison_plugins(self.comparison_plugins):
            comparison_results[plugin.NAME] = plugin.compare(fo_list, comparison_results)
        return comparison_results


def schedule_comparison_plugins(plugin_dict: dict[str, ComparisonBasePlugin]) -> list[ComparisonBasePlugin]:
    # we use a reverse topological sort for scheduling the plugins while considering their dependencies
    # see also: https://en.wikipedia.org/wiki/Topological_sorting#Depth-first_search
    visited = set()
    temp_mark = set()
    sorted_plugins = []

    def visit(plugin_):
        if plugin_.NAME in temp_mark:
            raise ValueError('Cyclic dependency or dependency cannot be scheduled')
        if plugin_.NAME not in visited:
            temp_mark.add(plugin_.NAME)
            for dependency in plugin_.COMPARISON_DEPS:
                if dependency not in plugin_dict:
                    raise ValueError(f'Unknown dependency: {dependency}')
                visit(plugin_dict[dependency])
            temp_mark.remove(plugin_.NAME)
            visited.add(plugin_.NAME)
            sorted_plugins.append(plugin_)

    for plugin in plugin_dict.values():
        try:
            visit(plugin)
        except ValueError as error:
            logging.error(f'Error: cannot schedule comparison plugin {plugin.NAME}: {error}')

    return sorted_plugins

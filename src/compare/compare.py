from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from helperFunctions.plugin import discover_compare_plugins
from helperFunctions.virtual_file_path import get_paths_for_all_parents
from objects.firmware import Firmware
from storage.binary_service import BinaryService
from storage.db_interface_comparison import ComparisonDbInterface

if TYPE_CHECKING:
    from helperFunctions.uid import UID
    from compare.PluginBase import CompareBasePlugin
    from objects.file import FileObject


class Compare:
    """
    This Module compares firmware images
    """

    def __init__(self, db_interface: ComparisonDbInterface | None = None):
        self.db_interface: ComparisonDbInterface = db_interface or ComparisonDbInterface()
        self.compare_plugins: dict[str, CompareBasePlugin] = {}
        self._load_plugins()
        logging.info(f'Comparison plugins available: {", ".join(self.compare_plugins)}')

    def compare(self, uid_list: list[UID]):
        logging.info(f'Comparison in progress: {uid_list}')
        binary_service = BinaryService()

        fo_list = []
        for uid in uid_list:
            fo = self.db_interface.get_complete_object_including_all_summaries(uid)
            fo.binary = binary_service.get_binary_and_file_name(fo.uid)[0]
            fo_list.append(fo)

        return self.compare_objects(fo_list)

    def compare_objects(self, fo_list: list[FileObject]) -> dict[str, dict[str, dict[str, Any]]]:
        return {
            'general': self._create_general_section_dict(fo_list),
            'plugins': self._execute_compare_plugins(fo_list),
        }

    def _create_general_section_dict(self, object_list) -> dict[str, dict[UID, Any]]:
        general: dict[str, dict[UID, Any]] = {}
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
                vfp_data[fo.uid] = [fo.file_name or 'unknown']  # file_name should always be initialized here
        return vfp_data

    # --- plug-in system ---

    def _load_plugins(self):
        for plugin in discover_compare_plugins():
            try:
                self.compare_plugins[plugin.ComparePlugin.NAME] = plugin.ComparePlugin(db_interface=self.db_interface)
            except Exception:
                logging.error(f'Could not initialize comparison plugin {plugin.__name__}', exc_info=True)

    def _execute_compare_plugins(self, fo_list: list[FileObject]) -> dict[str, dict]:
        return {name: plugin.compare(fo_list) for name, plugin in self.compare_plugins.items()}

import logging
from contextlib import suppress
from typing import Optional

from helperFunctions.plugin import import_plugins
from objects.firmware import Firmware
from storage.binary_service import BinaryService
from storage.db_interface_comparison import ComparisonDbInterface


class Compare:
    '''
    This Module compares firmware images
    '''

    compare_plugins = {}

    def __init__(self, db_interface: Optional[ComparisonDbInterface] = None):
        self.db_interface = db_interface
        self._setup_plugins()
        logging.info(f'Plug-ins available: {self.compare_plugins.keys()}')

    def compare(self, uid_list):
        logging.info(f'Compare in progress: {uid_list}')
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
            'plugins': self._execute_compare_plugins(fo_list),
        }

    def _create_general_section_dict(self, object_list):
        general = {}
        for fo in object_list:
            if isinstance(fo, Firmware):
                fo.root_uid = fo.uid
                self._add_content_to_general_dict(general, 'device_name', fo.uid, fo.device_name)
                self._add_content_to_general_dict(general, 'device_part', fo.uid, fo.part)
                self._add_content_to_general_dict(general, 'device_class', fo.uid, fo.device_class)
                self._add_content_to_general_dict(general, 'vendor', fo.uid, fo.vendor)
                self._add_content_to_general_dict(general, 'version', fo.uid, fo.version)
                self._add_content_to_general_dict(general, 'release_date', fo.uid, fo.release_date)
            else:
                self._add_content_to_general_dict(
                    general, 'firmwares_including_this_file', fo.uid, list(fo.get_virtual_file_paths().keys())
                )
            self._add_content_to_general_dict(general, 'hid', fo.uid, fo.get_hid())
            self._add_content_to_general_dict(general, 'size', fo.uid, fo.size)
            self._add_content_to_general_dict(general, 'virtual_file_path', fo.uid, fo.get_virtual_paths_for_all_uids())
            self._add_content_to_general_dict(general, 'number_of_files', fo.uid, len(fo.list_of_all_included_files))
        return general

    @staticmethod
    def _add_content_to_general_dict(general_dict, feature, uid, content):
        with suppress(Exception):
            if feature not in general_dict:
                general_dict[feature] = {}
            general_dict[feature][uid] = content

    # --- plug-in system ---

    def _setup_plugins(self):
        self.compare_plugins = {}
        self._init_plugins()

    def _init_plugins(self):
        self.source = import_plugins(
            'compare.plugins', 'plugins/compare'
        )  # pylint: disable=attribute-defined-outside-init
        for plugin_name in self.source.list_plugins():
            try:
                plugin = self.source.load_plugin(plugin_name)
            except Exception:  # pylint: disable=broad-except
                # For why this exception can occur see Analysis.AnalysisScheduler.load_plugins
                logging.error(f'Could not import plugin {plugin_name} due to exception', exc_info=True)
            else:
                self.compare_plugins[plugin.ComparePlugin.NAME] = plugin.ComparePlugin(db_interface=self.db_interface)

    def _execute_compare_plugins(self, fo_list):
        return {name: plugin.compare(fo_list) for name, plugin in self.compare_plugins.items()}

import logging
from contextlib import suppress

from helperFunctions.plugin import import_plugins
from objects.firmware import Firmware
from storage.binary_service import BinaryService


class Compare(object):
    '''
    This Module compares firmware images
    '''

    compare_plugins = {}

    def __init__(self, config=None, db_interface=None):
        '''
        Constructor
        '''
        self.config = config
        self.db_interface = db_interface
        self._setup_plugins()
        logging.info('Plug-ins available: {}'.format(list(self.compare_plugins.keys())))

    def compare(self, uid_list):
        logging.info('Compare in progress: {}'.format(uid_list))
        bs = BinaryService(config=self.config)

        fo_list = []
        for uid in uid_list:
            try:
                fo = self.db_interface.get_complete_object_including_all_summaries(uid)
                fo.binary = bs.get_binary_and_file_name(fo.uid)[0]
                fo_list.append(fo)
            except Exception as exception:
                return exception

        return self.compare_objects(fo_list)

    def compare_objects(self, fo_list):
        tmp = {}
        tmp['general'] = self._create_general_section_dict(fo_list)
        tmp['plugins'] = self._execute_compare_plugins(fo_list)
        return tmp

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
                self._add_content_to_general_dict(general, 'firmwares_including_this_file', fo.uid, list(fo.get_virtual_file_paths().keys()))
            self._add_content_to_general_dict(general, 'hid', fo.uid, fo.get_hid())
            self._add_content_to_general_dict(general, 'size', fo.uid, fo.size)
            self._add_content_to_general_dict(general, 'virtual_file_path', fo.uid, fo.get_virtual_paths_for_one_uid())
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
        self.source = import_plugins('compare.plugins', 'plugins/compare')
        for plugin_name in self.source.list_plugins():
            plugin = self.source.load_plugin(plugin_name)
            plugin.ComparePlugin(self, config=self.config, db_interface=self.db_interface)

    def register_plugin(self, name, c_plugin_instance):
        self.compare_plugins[name] = c_plugin_instance

    def _execute_compare_plugins(self, fo_list):
        plugin_results = {}
        for plugin in self.compare_plugins:
            plugin_results[plugin] = self.compare_plugins[plugin].compare(fo_list)
        return plugin_results

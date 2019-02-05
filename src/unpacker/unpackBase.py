import logging
import sys
from os import getgid, getuid
from subprocess import Popen, PIPE
from time import time

from common_helper_files import get_files_in_dir

from helperFunctions.config import read_list_from_config
from helperFunctions.fileSystem import get_file_type_from_path
from helperFunctions.plugin import import_plugins


class UnpackBase(object):
    '''
    The unpacker module unpacks all files included in a file
    '''

    def __init__(self, config=None, worker_id=None):
        self.config = config
        self.worker_id = worker_id
        self._setup_plugins()

    def _setup_plugins(self):
        self.unpacker_plugins = {}
        self.load_plugins()
        logging.info('[worker {}] Plug-ins available: {}'.format(self.worker_id, self.source.list_plugins()))
        self._set_whitelist()

    def load_plugins(self):
        self.source = import_plugins('unpacker.plugins', 'plugins/unpacking')
        for plugin_name in self.source.list_plugins():
            plugin = self.source.load_plugin(plugin_name)
            plugin.setup(self)

    def _set_whitelist(self):
        self.whitelist = read_list_from_config(self.config, 'unpack', 'whitelist')
        logging.debug('[worker {}] Ignore (Whitelist): {}'.format(self.worker_id, ', '.join(self.whitelist)))
        for item in self.whitelist:
            self.register_plugin(item, self.unpacker_plugins['generic/nop'])

    def register_plugin(self, mime_type, unpacker_name_and_function):
        self.unpacker_plugins[mime_type] = unpacker_name_and_function

    def get_unpacker(self, mime_type, object_depth):
        if object_depth > int(self.config['unpack']['max_depth']):
            logging.debug('[worker {}] max depth reached'.format(self.worker_id))
            return self.unpacker_plugins['generic/nop']
        else:
            if mime_type in list(self.unpacker_plugins.keys()):
                return self.unpacker_plugins[mime_type]
            else:
                return self.unpacker_plugins['generic/carver']

    @staticmethod
    def _get_unpacker_version(unpacker_tupple):
        if len(unpacker_tupple) == 3:
            return unpacker_tupple[2]
        else:
            return 'not set'

    def extract_files_from_file(self, file_path, tmp_dir, file_depth=0):
        current_unpacker = self.get_unpacker(get_file_type_from_path(file_path)['mime'], file_depth)
        return self._extract_files_from_file_using_specific_unpacker(file_path, tmp_dir, current_unpacker)

    def unpacking_fallback(self, file_path, tmp_dir, old_meta, fallback_plugin_mime):
        fallback_plugin = self.unpacker_plugins[fallback_plugin_mime]
        old_meta['0_FALLBACK_{}'.format(old_meta['plugin_used'])] = '{} (failed) -> {} (fallback)'.format(old_meta['plugin_used'], fallback_plugin_mime)
        if 'output' in old_meta.keys():
            old_meta['0_ERROR_{}'.format(old_meta['plugin_used'])] = old_meta['output']
        return self._extract_files_from_file_using_specific_unpacker(file_path, tmp_dir, fallback_plugin, meta_data=old_meta)

    def _extract_files_from_file_using_specific_unpacker(self, file_path, tmp_dir, selected_unpacker, meta_data=None):
        if meta_data is None:
            meta_data = {}
        meta_data['plugin_used'] = selected_unpacker[1]
        meta_data['plugin_version'] = self._get_unpacker_version(selected_unpacker)
        logging.debug('[worker {}] Try to unpack {} with {} plugin...'.format(self.worker_id, file_path, meta_data['plugin_used']))
        try:
            additional_meta = selected_unpacker[0](file_path, tmp_dir)
        except Exception as e:
            logging.debug('[worker {}] Unpacking of {} failed: {}: {}'.format(self.worker_id, file_path, sys.exc_info()[0].__name__, e))
            additional_meta = {'error': '{}: {}'.format(sys.exc_info()[0].__name__, e.__str__())}
        if isinstance(additional_meta, dict):
            meta_data.update(additional_meta)
        self.change_owner_back_to_me(directory=tmp_dir)
        meta_data['analysis_date'] = time()
        return get_files_in_dir(tmp_dir), meta_data

    def change_owner_back_to_me(self, directory=None, permissions='u+r'):
        with Popen('sudo chown -R {}:{} {}'.format(getuid(), getgid(), directory), shell=True, stdout=PIPE, stderr=PIPE) as pl:
            pl.communicate()
        self.grant_read_permission(directory, permissions)

    @staticmethod
    def grant_read_permission(directory, permissions):
        with Popen('chmod --recursive {} {}'.format(permissions, directory), shell=True, stdout=PIPE, stderr=PIPE) as pl:
            pl.communicate()

from hashlib import algorithms_available
import logging

from helperFunctions.config import read_list_from_config
from helperFunctions.hash import get_hash, get_ssdeep, get_imphash, get_tlsh
from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This Plugin creates several hashes of the file
    '''
    NAME = 'file_hashes'
    DEPENDENCIES = ['file_type']
    DESCRIPTION = 'calculate different hash values of the file'
    VERSION = '1.1'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config
        self.hashes_to_create = self._get_hash_list_from_config()

        # additional init stuff can go here

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__, timeout=600)

    def process_object(self, file_object):
        '''
        This function must be implemented by the plugin.
        Analysis result must be a dict stored in file_object.processed_analysis[self.NAME]
        If you want to propagate results to parent objects store a list of strings 'summary' entry of your result dict
        '''
        file_object.processed_analysis[self.NAME] = {}
        for h in self.hashes_to_create:
            if h in algorithms_available:
                file_object.processed_analysis[self.NAME][h] = get_hash(h, file_object.binary)
            else:
                logging.debug('algorithm {} not available'.format(h))
        file_object.processed_analysis[self.NAME]['ssdeep'] = get_ssdeep(file_object.binary)
        file_object.processed_analysis[self.NAME]['imphash'] = get_imphash(file_object)

        tlsh_hash = get_tlsh(file_object.binary)
        if tlsh_hash:
            file_object.processed_analysis[self.NAME]['tlsh'] = get_tlsh(file_object.binary)

        return file_object

    def _get_hash_list_from_config(self):
        try:
            return read_list_from_config(self.config, self.NAME, 'hashes', default=['sha256'])
        except Exception:
            logging.warning("'file_hashes' -> 'hashes' not set in config")
            return ['sha256']

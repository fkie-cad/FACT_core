from hashlib import algorithms_available
import logging

from helperFunctions.config import read_list_from_config
from helperFunctions.hash import get_hash, get_ssdeep, get_imphash
from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This Plugin creates several hashes of the file
    '''
    NAME = 'file_hashes'
    DEPENDENCIES = ['file_type']
    DESCRIPTION = 'calculate different hash values of the file'
    VERSION = '1.0'

    def __init__(self, config=None):
        self.config = config
        self.hashes_to_create = self._get_hash_list_from_config()

        super().__init__(config=self.config, plugin_path=__file__)

    def process_object(self, file_object):
        '''
        This function must be implemented by the plugin.
        Analysis result must be a dict stored in file_object.processed_analysis[self.NAME]
        If you want to propagate results to parent objects store a list of strings 'summary' entry of your result dict
        '''
        file_object.processed_analysis[self.NAME] = {}
        for hash_ in self.hashes_to_create:
            if hash_ in algorithms_available:
                file_object.processed_analysis[self.NAME][hash_] = get_hash(hash_, file_object.binary)
            else:
                logging.debug('algorithm {} not available'.format(hash_))
        file_object.processed_analysis[self.NAME]['ssdeep'] = get_ssdeep(file_object.binary)
        file_object.processed_analysis[self.NAME]['imphash'] = get_imphash(file_object)
        return file_object

    def _get_hash_list_from_config(self):
        try:
            return read_list_from_config(self.config, self.NAME, 'hashes', default=['sha256'])
        except (TypeError, AttributeError, KeyError):
            logging.warning("'file_hashes' -> 'hashes' not set in config")
            return ['sha256']

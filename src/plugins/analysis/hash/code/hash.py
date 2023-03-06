import logging
from hashlib import algorithms_guaranteed

import config
from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.hash import get_hash, get_imphash, get_ssdeep, get_tlsh


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This Plugin creates several hashes of the file
    '''

    NAME = 'file_hashes'
    DEPENDENCIES = ['file_type']
    DESCRIPTION = 'calculate different hash values of the file'
    VERSION = '1.2'
    FILE = __file__

    def additional_setup(self):
        hashes = getattr(config.backend.plugin.get(self.NAME, None), 'hashes', ['sha256'])
        self.hashes_to_create = hashes

    def process_object(self, file_object):
        '''
        This function must be implemented by the plugin.
        Analysis result must be a dict stored in file_object.processed_analysis[self.NAME]
        If you want to propagate results to parent objects store a list of strings 'summary' entry of your result dict
        '''
        file_object.processed_analysis[self.NAME] = {}
        for hash_ in self.hashes_to_create:
            if hash_ in algorithms_guaranteed:
                file_object.processed_analysis[self.NAME][hash_] = get_hash(hash_, file_object.binary)
            else:
                logging.debug(f'algorithm {hash_} not available')
        file_object.processed_analysis[self.NAME]['ssdeep'] = get_ssdeep(file_object.binary)
        file_object.processed_analysis[self.NAME]['imphash'] = get_imphash(file_object)

        tlsh_hash = get_tlsh(file_object.binary)
        if tlsh_hash:
            file_object.processed_analysis[self.NAME]['tlsh'] = get_tlsh(file_object.binary)

        return file_object

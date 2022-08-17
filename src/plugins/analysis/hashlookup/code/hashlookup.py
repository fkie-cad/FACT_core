import json
import logging

import requests

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED, MIME_BLACKLIST_NON_EXECUTABLE


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'hashlookup'
    DESCRIPTION = (
        'Querying the circ.lu hash library to identify known binaries. The library contains file hashes for multiple'
        '*nix distributions and the NIST software reference library.'
    )
    MIME_BLACKLIST = [*MIME_BLACKLIST_NON_EXECUTABLE, *MIME_BLACKLIST_COMPRESSED]
    DEPENDENCIES = ['file_hashes']
    VERSION = '0.1.4'
    FILE = __file__

    def process_object(self, file_object: FileObject):
        try:
            sha2_hash = file_object.processed_analysis['file_hashes']['sha256']
        except KeyError:
            message = 'Lookup needs sha256 hash of file. It\'s missing so sth. seems to be wrong with the hash plugin'
            logging.error(message)
            file_object.processed_analysis[self.NAME] = {
                'failed': message,
                'summary': [],
            }
            return file_object

        try:
            result = requests.get(
                f'https://hashlookup.circl.lu/lookup/sha256/{sha2_hash}',
                headers={'accept': 'application/json'}
            ).json()
        except (requests.ConnectionError,  json.JSONDecodeError):
            logging.error('Failed to connect to circ.lu hashlookup API', exc_info=True)
            result = {}

        if 'FileName' in result:
            result['summary'] = [result['FileName']]
            file_object.processed_analysis[self.NAME] = result
        elif 'message' in result and result['message'] == 'Non existing SHA-256':
            file_object.processed_analysis[self.NAME] = {
                'message': 'sha256 hash unknown to hashlookup at time of analysis',
                'summary': [],
            }
        else:
            file_object.processed_analysis[self.NAME] = {
                'failed': 'Unknown error connecting to hashlookup API',
                'summary': [],
            }
        return file_object

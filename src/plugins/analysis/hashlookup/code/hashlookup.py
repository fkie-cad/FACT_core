import logging

import requests

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject

CONTAINER_FORMATS = [
    'application/gzip', 'application/x-7z-compressed', 'application/x-archive', 'application/x-bzip2',
    'application/x-cpio', 'application/x-lzma', 'application/x-tar', 'application/x-xz', 'application/zip'
]


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'hashlookup'
    DESCRIPTION = (
        'Querying the circ.lu hash library to identify known binaries. The library contains file hashes for multiple'
        '*nix distributions and the NIST software reference library.'
    )
    MIME_BLACKLIST = ['audio/', 'compression/', 'filesystem/', 'font/', 'image/', 'video/', *CONTAINER_FORMATS]
    DEPENDENCIES = ['file_hashes']
    VERSION = '0.1.3'

    def __init__(self, plugin_administrator, config=None, recursive=True, offline_testing=False):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__, offline_testing=offline_testing)

    def process_object(self, file_object: FileObject):
        try:
            sha2_hash = file_object.processed_analysis['file_hashes']['sha256']
        except (AttributeError, KeyError):
            message = 'Lookup needs sha256 hash of file. It\'s missing so sth. seems to be wrong with the hash plugin'
            logging.error(message)
            file_object.processed_analysis[self.NAME] = {
                'message': message,
                'summary': []
            }
            return file_object

        result = requests.get(
            f'https://hashlookup.circl.lu/lookup/sha256/{sha2_hash}',
            headers={'accept': 'application/json'}
        ).json()

        if 'FileName' in result:
            result['summary'] = [result['FileName']]
            file_object.processed_analysis[self.NAME] = result
        elif 'message' in result and result['message'] == 'Non existing SHA-256':
            file_object.processed_analysis[self.NAME] = {
                'message': 'sha256 hash unknown to hashlookup at time of analysis',
                'summary': []
            }
        else:
            file_object.processed_analysis[self.NAME] = {
                'message': 'Unknown error connecting to hashlookup API',
                'summary': []
            }
        return file_object

from itertools import chain

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.database import ConnectTo
from helperFunctions.hash import get_tlsh_comparison
from storage.db_interface_common import MongoInterfaceCommon


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    TLSH Plug-in
    '''
    NAME = 'tlsh'
    DESCRIPTION = 'find files with similar tlsh and calculate similarity value'
    DEPENDENCIES = ['file_hashes']
    VERSION = '0.1'

    def __init__(self, plugin_adminstrator, config=None, recursive=True, offline_testing=False):
        super().__init__(plugin_adminstrator, config=config, recursive=recursive, plugin_path=__file__, offline_testing=offline_testing)

    def process_object(self, file_object):
        comparisons_dict = {}
        if 'tlsh' in file_object.processed_analysis['file_hashes'].keys():
            with ConnectTo(TLSHInterface, self.config) as interface:
                for file in interface.tlsh_query_all_objects():
                    value = get_tlsh_comparison(file_object.processed_analysis['file_hashes']['tlsh'], file['processed_analysis']['file_hashes']['tlsh'])
                    if value <= 150 and not file['_id'] == file_object.uid:
                        comparisons_dict[file['_id']] = value

        file_object.processed_analysis[self.NAME] = comparisons_dict
        return file_object


class TLSHInterface(MongoInterfaceCommon):
    READ_ONLY = True

    def tlsh_query_all_objects(self):
        fields = {'processed_analysis.file_hashes.tlsh': 1}

        return chain(
            self.file_objects.find({'processed_analysis.file_hashes.tlsh': {'$exists': True}}, fields),
            self.firmwares.find({'processed_analysis.file_hashes.tlsh': {'$exists': True}}, fields)
        )

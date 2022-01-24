from sqlalchemy import select

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.hash import get_tlsh_comparison
from storage.db_interface_base import ReadOnlyDbInterface
from storage.schema import AnalysisEntry


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    TLSH Plug-in
    '''
    NAME = 'tlsh'
    DESCRIPTION = 'find files with similar tlsh and calculate similarity value'
    DEPENDENCIES = ['file_hashes']
    VERSION = '0.2'

    def __init__(self, plugin_administrator, config=None, recursive=True, offline_testing=False):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__, offline_testing=offline_testing)
        self.db = TLSHInterface(config)

    def process_object(self, file_object):
        comparisons_dict = {}
        if 'tlsh' in file_object.processed_analysis['file_hashes'].keys():
            for file in self.db.get_all_tlsh_hashes():
                value = get_tlsh_comparison(file_object.processed_analysis['file_hashes']['tlsh'], file['processed_analysis']['file_hashes']['tlsh'])
                if value <= 150 and not file['_id'] == file_object.uid:
                    comparisons_dict[file['_id']] = value

        file_object.processed_analysis[self.NAME] = comparisons_dict
        return file_object


class TLSHInterface(ReadOnlyDbInterface):
    def get_all_tlsh_hashes(self):
        with self.get_read_only_session() as session:
            query = select(AnalysisEntry.result['tlsh']).filter(AnalysisEntry.plugin == 'file_hashes')
            return list(session.execute(query).scalars())

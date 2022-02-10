from typing import List, Tuple

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
    FILE = __file__

    def __init__(self, *args, config=None, db_interface=None, **kwargs):
        self.db = TLSHInterface(config) if db_interface is None else db_interface
        super().__init__(*args, config=config, **kwargs)

    def process_object(self, file_object):
        comparisons_dict = {}
        if 'tlsh' in file_object.processed_analysis['file_hashes'].keys():
            for uid, tlsh_hash in self.db.get_all_tlsh_hashes():
                value = get_tlsh_comparison(file_object.processed_analysis['file_hashes']['tlsh'], tlsh_hash)
                if value <= 150 and not uid == file_object.uid:
                    comparisons_dict[uid] = value

        file_object.processed_analysis[self.NAME] = comparisons_dict
        return file_object


class TLSHInterface(ReadOnlyDbInterface):
    def get_all_tlsh_hashes(self) -> List[Tuple[str, str]]:
        with self.get_read_only_session() as session:
            query = (
                select(AnalysisEntry.uid, AnalysisEntry.result['tlsh'])
                .filter(AnalysisEntry.plugin == 'file_hashes')
                .filter(AnalysisEntry.result['tlsh'] != None)  # noqa: E711  # pylint: disable=singleton-comparison
            )
            return list(session.execute(query))

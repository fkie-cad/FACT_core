from __future__ import annotations

from sqlalchemy import select

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.hash import get_tlsh_comparison
from storage.db_interface_base import ReadOnlyDbInterface
from storage.schema import AnalysisEntry


class AnalysisPlugin(AnalysisBasePlugin):
    """
    TLSH Plug-in
    """

    NAME = 'tlsh'
    DESCRIPTION = 'find files with similar tlsh and calculate similarity value'
    DEPENDENCIES = ['file_hashes']  # noqa: RUF012
    VERSION = '0.2'
    FILE = __file__

    def __init__(self, *args, **kwargs):
        self.db = TLSHInterface()
        super().__init__(*args, **kwargs)

    def process_object(self, file_object):
        comparisons_dict = {}
        if 'tlsh' in file_object.processed_analysis['file_hashes']['result']:
            for uid, tlsh_hash in self.db.get_all_tlsh_hashes():
                value = get_tlsh_comparison(file_object.processed_analysis['file_hashes']['result']['tlsh'], tlsh_hash)
                if value <= 150 and uid != file_object.uid:  # noqa: PLR2004
                    comparisons_dict[uid] = value

        file_object.processed_analysis[self.NAME] = comparisons_dict
        return file_object


class TLSHInterface(ReadOnlyDbInterface):
    def get_all_tlsh_hashes(self) -> list[tuple[str, str]]:
        with self.get_read_only_session() as session:
            query = (
                select(AnalysisEntry.uid, AnalysisEntry.result['tlsh'])
                .filter(AnalysisEntry.plugin == 'file_hashes')
                .filter(AnalysisEntry.result['tlsh'] != None)  # noqa: E711
            )
            return list(session.execute(query))

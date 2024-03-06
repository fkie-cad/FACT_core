from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.tag import TagColor
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

if TYPE_CHECKING:
    from objects.file import FileObject

try:
    from ..internal.database.db_connection import DbConnection
    from ..internal.lookup import Lookup
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from database.db_connection import DbConnection
    from lookup import Lookup

DB_PATH = str(Path(__file__).parent / '../internal/database/cve_cpe.db')


class AnalysisPlugin(AnalysisBasePlugin):
    """
    lookup vulnerabilities from CVE feeds using ID from CPE dictionary
    """

    NAME = 'cve_lookup'
    DESCRIPTION = 'lookup CVE vulnerabilities'
    MIME_BLACKLIST = MIME_BLACKLIST_NON_EXECUTABLE
    DEPENDENCIES = ['software_components']  # noqa: RUF012
    VERSION = '0.1.0'
    FILE = __file__

    def process_object(self, file_object: FileObject) -> FileObject:
        """
        Process the given file object and look up vulnerabilities for each software component.
        """
        cves = {'cve_results': {}}
        connection = DbConnection(f'sqlite:///{DB_PATH}')
        lookup = Lookup(file_object, connection)
        for value in file_object.processed_analysis['software_components']['result'].values():
            product = value['meta']['software_name']
            version = value['meta']['version'][0]
            if product and version:
                vulnerabilities = lookup.lookup_vulnerabilities(product, version)
                if vulnerabilities:
                    component = f'{product} {version}'
                    cves['cve_results'][component] = vulnerabilities

        cves['summary'] = self._create_summary(cves['cve_results'])
        file_object.processed_analysis[self.NAME] = cves
        self.add_tags(cves['cve_results'], file_object)
        return file_object

    def _create_summary(self, cve_results: dict[str, dict[str, dict[str, str]]]) -> list[str]:
        """
        Creates a summary of the CVE results.
        """
        return list(
            {
                software if not self._software_has_critical_cve(entry) else f'{software} (CRITICAL)'
                for software, entry in cve_results.items()
            }
        )

    def _software_has_critical_cve(self, cve_dict: dict[str, dict[str, str]]) -> bool:
        """
        Check if any entry in the given dictionary of CVEs has a critical rating.
        """
        return any(self._entry_has_critical_rating(entry) for entry in cve_dict.values())

    def add_tags(self, cve_results: dict[str, dict[str, dict[str, str]]], file_object: FileObject):
        """
        Adds analysis tags to a file object based on the critical CVE results.

        Results structure: {'component': {'cve_id': {'score2': '6.4', 'score3': 'N/A'}}}
        """
        for component in cve_results:
            for cve_id in cve_results[component]:
                entry = cve_results[component][cve_id]
                if self._entry_has_critical_rating(entry):
                    self.add_analysis_tag(file_object, 'CVE', 'critical CVE', TagColor.RED, True)
                    return

    @staticmethod
    def _entry_has_critical_rating(entry: dict[str, str]) -> bool:
        """
        Check if the given entry has a critical rating.
        """
        return any(entry[key] != 'N/A' and float(entry[key]) >= 9.0 for key in ['score2', 'score3'])  # noqa: PLR2004

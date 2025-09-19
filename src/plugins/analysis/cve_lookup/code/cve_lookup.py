from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, List

from pydantic import BaseModel
from semver import Version

import config
from analysis.plugin import AnalysisPluginV0, Tag
from helperFunctions.tag import TagColor
from plugins.analysis.cve_lookup.internal.database.db_connection import DbConnection
from plugins.analysis.cve_lookup.internal.lookup import CveMatch, CvssScore, Lookup
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

if TYPE_CHECKING:
    from io import FileIO

    from plugins.analysis.software_components.code.software_components import AnalysisPlugin as SoftwarePlugin

DB_PATH = str(Path(__file__).parent / '../internal/database/cve_cpe.db')


class CveResult(BaseModel):
    software_name: str
    cve_list: List[CveMatch]

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            raise TypeError(f'Wrong type: {type(other)}')
        return self.software_name < other.software_name  # to enable sorting


class AnalysisPlugin(AnalysisPluginV0):
    """
    lookup vulnerabilities from CVE feeds using ID from CPE dictionary
    """

    class Schema(BaseModel):
        cve_results: List[CveResult]

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='cve_lookup',
                    description='lookup CVE vulnerabilities',
                    mime_blacklist=MIME_BLACKLIST_NON_EXECUTABLE,
                    version=Version(1, 0, 0),
                    dependencies=['software_components'],
                    Schema=self.Schema,
                )
            )
        )
        self.min_crit_score = getattr(config.backend.plugin.get(self.metadata.name, {}), 'min-critical-score', 9.0)
        self.match_any = getattr(config.backend.plugin.get(self.metadata.name, {}), 'match-any', False)

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]) -> Schema:
        """
        Process the given file object and look up vulnerabilities for each software component.
        """
        del virtual_file_path
        connection = DbConnection(f'sqlite:///{DB_PATH}')

        cve_results = []
        lookup = Lookup(file_handle.name, connection, match_any=self.match_any)
        sw_analysis: SoftwarePlugin.Schema = analyses['software_components']
        for sw_dict in sw_analysis.software_components:
            product = sw_dict.name
            version = sw_dict.versions[0] if sw_dict.versions else None
            if product and version:
                vulnerabilities = lookup.lookup_vulnerabilities(product, version)
                if vulnerabilities:
                    component = f'{product} {version}'
                    cve_results.append(
                        CveResult(
                            software_name=component,
                            cve_list=vulnerabilities,
                        )
                    )

        return self.Schema(cve_results=cve_results)

    def summarize(self, result: Schema) -> list[str]:
        summary = {
            entry.software_name
            if not self._software_has_critical_cve(entry.cve_list)
            else f'{entry.software_name} (CRITICAL)'
            for entry in result.cve_results
        }
        return sorted(summary)

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del summary
        return [
            Tag(name='CVE', value='critical CVE', color=TagColor.RED, propagate=True)
            for component in result.cve_results
            for cve in component.cve_list
            if self._entry_has_critical_rating(cve.scores)
        ]

    def _software_has_critical_cve(self, cve_list: List[CveMatch]) -> bool:
        """
        Check if any entry in the given dictionary of CVEs has a critical rating.
        """
        return any(self._entry_has_critical_rating(entry.scores) for entry in cve_list)

    def _entry_has_critical_rating(self, scores: list[CvssScore]) -> bool:
        """
        Check if the given entry has a critical rating.
        """
        return any(entry.score != 'N/A' and float(entry.score) >= self.min_crit_score for entry in scores)

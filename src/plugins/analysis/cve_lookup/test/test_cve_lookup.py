from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from plugins.analysis.cve_lookup.code import cve_lookup
from plugins.analysis.cve_lookup.internal.database.db_connection import DbConnection
from plugins.analysis.cve_lookup.internal.database.db_setup import DbSetup
from plugins.analysis.cve_lookup.internal.helper_functions import CveEntry
from plugins.analysis.cve_lookup.internal.lookup import CveMatch, CvssScore
from plugins.analysis.software_components.code.software_components import AnalysisPlugin as SoftwarePlugin
from test.common_helper import TEST_FW

# Set the temp path for the DB
temp_dir = tempfile.TemporaryDirectory()
db_path = temp_dir.name

# Update the DB_PATH variable
cve_lookup.DB_PATH = f'{db_path}/test.db'

SOFTWARE_COMPONENTS_ANALYSIS_RESULT = {
    'software_components': [
        {
            'name': 'Dnsmasq',
            'description': '',
            'open_source': True,
            'versions': ['2.40'],
            'website': '',
            'rule': 'dnsmasq',
            'matching_strings': [],
        },
        {
            'name': 'OpenSSL',
            'description': 'SSL library',
            'open_source': True,
            'versions': [],
            'website': 'https://www.openssl.org',
            'rule': 'OpenSSL',
            'matching_strings': [{'offset': 7194, 'identifier': '$a', 'string': 'T1BFTlNTTA=='}],
        },
    ],
}

CVE_ENTRY1 = CveEntry(
    cve_id='CVE-2013-0198',
    summary='Dnsmasq before 2.66test2, when used with certain libvirt configurations, replies to queries from prohibited interfaces, which allows remote attackers to cause a denial of service (traffic amplification) via spoofed TCP based DNS queries. NOTE: this vulnerability exists because of an incomplete fix for CVE-2012-3411.',  # noqa: E501
    impact={'cvssMetricV2': 5.0},
    cpe_entries=[('cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*', '', '', '2.65', '')],
)

CVE_ENTRY2 = CveEntry(
    cve_id='CVE-2017-14493',
    summary='Stack-based buffer overflow in dnsmasq before 2.78 allows remote attackers to cause a denial of service (crash) or execute arbitrary code via a crafted DHCPv6 request.',  # noqa: E501
    impact={'cvssMetricV2': 7.5, 'cvssMetricV30': 9.8},
    cpe_entries=[
        ('cpe:2.3:o:canonical:ubuntu_linux:14.04:*:*:*:lts:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:canonical:ubuntu_linux:16.04:*:*:*:lts:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:canonical:ubuntu_linux:17.04:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:debian:debian_linux:7.0:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:debian:debian_linux:7.1:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:debian:debian_linux:9.0:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:opensuse:leap:42.2:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:opensuse:leap:42.3:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:redhat:enterprise_linux_desktop:7.0:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:redhat:enterprise_linux_server:7.0:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:o:redhat:enterprise_linux_workstation:7.0:*:*:*:*:*:*:*', '', '', '', ''),
        ('cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*', '', '', '2.77', ''),
    ],
)


@pytest.mark.AnalysisPluginTestConfig(plugin_class=cve_lookup.AnalysisPlugin)
class TestCveLookup:
    def test_process_object(self, analysis_plugin: cve_lookup.AnalysisPlugin):
        connection_string = f'sqlite:///{db_path}/test.db'
        connection = DbConnection(connection_string)
        db_setup = DbSetup(connection)
        db_setup.add_cve_items([CVE_ENTRY1, CVE_ENTRY2])
        dependencies = {'software_components': SoftwarePlugin.Schema(**SOFTWARE_COMPONENTS_ANALYSIS_RESULT)}

        with Path(TEST_FW.file_path).open('rb') as fp:
            result = analysis_plugin.analyze(fp, {}, dependencies)
        summary = analysis_plugin.summarize(result)
        tags = analysis_plugin.get_tags(result, summary)
        result_by_sw = {r.software_name: r for r in result.cve_results}

        assert 'Dnsmasq 2.40 (CRITICAL)' in summary
        assert 'Dnsmasq 2.40' in result_by_sw
        assert any(cve.id == 'CVE-2013-0198' for cve in result_by_sw['Dnsmasq 2.40'].cve_list)
        assert len(tags) == 1
        assert tags[0].value == 'critical CVE'

    @pytest.mark.parametrize(('cve_score', 'should_be_tagged'), [('9.9', True), ('5.5', False)])
    def test_get_tags(self, analysis_plugin, cve_score, should_be_tagged):
        TEST_FW.processed_analysis['cve_lookup'] = {}
        cve_results = _generate_analysis_result([{'V2': cve_score, 'V3.1': 'N/A'}])
        tags = analysis_plugin.get_tags(cve_results, [])
        if should_be_tagged:
            assert len(tags) == 1
            assert tags[0].name == 'CVE'
            assert tags[0].value == 'critical CVE'
        else:
            assert len(tags) == 0

    @pytest.mark.parametrize(
        ('scores', 'expected_output'),
        [
            ({}, []),
            ([{'V2': '6.4', 'V3.1': 'N/A'}], ['component']),
            ([{'V2': '9.4', 'V3.1': 'N/A'}], ['component (CRITICAL)']),
            ([{'V2': '1.1', 'V3.1': '9.9'}, {'V2': '1.1', 'V3.1': '0.0'}], ['component (CRITICAL)']),
        ],
    )
    def test_create_summary(self, scores, expected_output, analysis_plugin):
        assert analysis_plugin.summarize(_generate_analysis_result(scores)) == expected_output


def _generate_analysis_result(scores: list[dict]):
    return cve_lookup.AnalysisPlugin.Schema(
        cve_results=[
            cve_lookup.CveResult(
                software_name='component',
                cve_list=[
                    CveMatch(
                        id='CVE-0',
                        cpe_version='0',
                        scores=[CvssScore(version=v, score=s) for v, s in score_dict.items()],
                    )
                    for score_dict in scores
                ],
            )
        ]
        if scores
        else [],
    )

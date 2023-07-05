import pytest
from ..code import cve_lookup
from test.common_helper import TEST_FW
from ..internal.db_setup import DbSetup
from ..internal.helper_functions import CveEntry
from ..internal.db_connection import DbConnection

SOFTWARE_COMPONENTS_ANALYSIS_RESULT = {
    'result': {
        'dnsmasq': {'meta': {'software_name': 'Dnsmasq', 'version': ['2.40']}},
        'OpenSSL': {
            'matches': True,
            'meta': {
                'description': 'SSL library',
                'open_source': True,
                'software_name': 'OpenSSL',
                'version': [''],
                'website': 'https://www.openssl.org',
            },
            'rule': 'OpenSSL',
            'strings': [[7194, '$a', 'T1BFTlNTTA==']],
        },
    },
    'analysis_date': 1563453634.37708,
    'plugin_version': '0.3.2',
    'summary': ['OpenSSL ', 'Dnsmasq 2.40'],
    'system_version': '3.7.1_1560435912',
}

CVE_ENTRY = CveEntry(
    cve_id='CVE-2013-0198',
    summary='Dnsmasq before 2.66test2, when used with certain libvirt configurations, replies to queries from prohibited interfaces, which allows remote attackers to cause a denial of service (traffic amplification) via spoofed TCP based DNS queries. NOTE: this vulnerability exists because of an incomplete fix for CVE-2012-3411.',
    impact={'cvssMetricV2': 5.0},
    cpe_entries=[('cpe:2.3:a:thekelleys:dnsmasq:*:*:*:*:*:*:*:*', '', '', '2.65', '')],
)

# cve_lookup.DB_PATH = ':memory:'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=cve_lookup.AnalysisPlugin)
class TestCveLookup:
    def setup_method(self):
        connection_string = 'sqlite:///:memory:'
        connection = DbConnection(connection_string)
        connection.create_tables()
        self.db_setup = DbSetup(connection)
        cve_list = [CVE_ENTRY]
        self.db_setup.add_cve_items(cve_list)

    def test_process_object(self, analysis_plugin):
        TEST_FW.processed_analysis['software_components'] = SOFTWARE_COMPONENTS_ANALYSIS_RESULT
        result = analysis_plugin.process_object(TEST_FW).processed_analysis['cve_lookup']
        assert 'Dnsmasq 2.40 (CRITICAL)' in result['summary']
        assert 'Dnsmasq 2.40' in result['cve_results']
        assert 'CVE-2013-0198' in result['cve_results']['Dnsmasq 2.40']

    @pytest.mark.parametrize(
        ('cve_results_dict', 'expected_output'),
        [
            ({}, []),
            ({'component': {'cve_id': {'score2': '6.4', 'score3': 'N/A'}}}, ['component']),
            ({'component': {'cve_id': {'score2': '9.4', 'score3': 'N/A'}}}, ['component (CRITICAL)']),
            (
                {
                    'component': {
                        'cve_id': {'score2': '1.1', 'score3': '9.9'},
                        'cve_id2': {'score2': '1.1', 'score3': '0.0'},
                    }
                },
                ['component (CRITICAL)'],
            ),
        ],
    )
    def test_create_summary(self, cve_results_dict, expected_output, analysis_plugin):
        assert analysis_plugin._create_summary(cve_results_dict) == expected_output  # pylint: disable=protected-access


@pytest.mark.parametrize(
    ('software_name', 'expected_output'),
    [
        ('windows 7', ['windows', 'windows_7']),
        ('Linux Kernel', ['linux', 'linux_kernel', 'kernel']),
    ],
)
def test_generate_search_terms(software_name, expected_output):
    result = cve_lookup.generate_search_terms(software_name)
    assert result == expected_output
    assert result == expected_output

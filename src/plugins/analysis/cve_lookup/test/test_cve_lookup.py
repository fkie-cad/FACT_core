import sys
from os import remove
from pathlib import Path

import pytest

from test.common_helper import TEST_FW, get_config_for_testing  # pylint: disable=wrong-import-order

try:
    from ..code import cve_lookup as lookup
    from ..internal.database_interface import DatabaseInterface
    from ..internal.helper_functions import replace_characters_and_wildcards
except ImportError:
    ROOT = Path(__file__).parent.parent
    sys.path.extend([str(ROOT / 'code'), str(ROOT / 'internal')])
    import vuln_lookup_plugin as lookup
    from database_interface import DatabaseInterface
    from helper_functions import replace_characters_and_wildcards


# pylint: disable=redefined-outer-name
lookup.MAX_LEVENSHTEIN_DISTANCE = 3

USER_INPUT = {'vendor': 'Microsoft', 'product': 'Windows 7', 'version': '1.2.5'}

MATCHED_CPE = [
    lookup.Product('microsoft', 'windows_8', '1\\.2\\.5'),
    lookup.Product('microsoft', 'windows_7', '1\\.3\\.1'),
    lookup.Product('mircosof', 'windows_7', '0\\.7')
]
MATCHED_CVE = ['CVE-1234-0010', 'CVE-1234-0011']
CPE_CVE_OUTPUT = [
    ('CVE-1234-0008', 'microsoft', 'server_2013', '2013', '10.0', '7.0', '1.2', '', '3.4', ''),
    ('CVE-1234-0009', 'mircosof', 'windows_7', '0\\.7', '10.0', '7.0', '1.2', '', '3.4', ''),
    ('CVE-1234-0010', 'microsoft', 'windows_8', '1\\.2\\.5', '10.0', '7.0', '1.2', '', '3.4', ''),
    ('CVE-1234-0011', 'microsoft', 'windows_8', 'ANY', '10.0', '7.0', '1.2', '', '3.4', ''),
    ('CVE-1234-0012', 'linux', 'linux_kernel', '2\\.2.\\3', '10.0', '7.0', '1.2', '', '3.4', ''),
]

MATCHED_SUMMARY = ['CVE-1234-0005', 'CVE-1234-0006', 'CVE-1234-0007']
SUMMARY_OUTPUT = [
    ('CVE-1234-0001', 'Attacker gains remote access', '5.0', '7.0'),
    ('CVE-1234-0002', 'Attacker gains remote access to microsoft windows', '5.0', '7.0'),
    ('CVE-1234-0003', 'Attacker gains remote access to microsoft server 2018', '5.0', '7.0'),
    ('CVE-1234-0004', 'Attacker gains remote access to microsoft windows 2018', '5.0', '7.0'),
    ('CVE-1234-0005', 'Attacker gains remote access to microsoft windows 8', '5.0', '7.0'),
    ('CVE-1234-0006', 'Attacker gains remote access to microsoft windows 7', '5.0', '7.0'),
    ('CVE-1234-0007', 'Attacker gains remote access to microsoft corporation windows 7', '5.0', '7.0'),
]

PRODUCT_SEARCH_TERMS = ['windows', 'windows_7']
VERSION_SEARCH_TERM = '1\\.2\\.5'
CPE_DATABASE_OUTPUT = [('microsoft', 'server_2013', '2013'),
                       ('mircosof', 'windows_7', '0\\.7'),
                       ('microsoft', 'windows_8', '1\\.2\\.5'),
                       ('microsoft', 'windows_7', '1\\.3\\.1'),
                       ('linux', 'linux_kernel', '2\\.2.\\3')]

SUMMARY_INPUT = ''

SORT_CPE_MATCHES_OUTPUT = lookup.Product('microsoft', 'windows_8', '1\\.2\\.5')

SOFTWARE_COMPONENTS_ANALYSIS_RESULT = {
    'dnsmasq': {
        'meta': {
            'software_name': 'Dnsmasq',
            'version': ['2.40']
        }
    },
    'OpenSSL': {
        'matches': True,
        'meta': {
            'description': 'SSL library',
            'open_source': True,
            'software_name': 'OpenSSL',
            'version': [''],
            'website': 'https://www.openssl.org'
        },
        'rule': 'OpenSSL',
        'strings': [[7194, '$a', 'T1BFTlNTTA==']]
    },
    'analysis_date': 1563453634.37708,
    'plugin_version': '0.3.2',
    'summary': [
        'OpenSSL ',
        'Dnsmasq 2.40'
    ],
    'system_version': '3.7.1_1560435912',
}


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    yield None
    try:
        remove('test.db')
    except OSError:
        pass


@pytest.mark.parametrize('software_name, expected_output', [
    ('windows 7', ['windows', 'windows_7']),
    ('Linux Kernel', ['linux', 'linux_kernel', 'kernel']),
])
def test_generate_search_terms(software_name, expected_output):
    result = lookup.generate_search_terms(software_name)
    assert result == expected_output
    assert replace_characters_and_wildcards(result) == expected_output


@pytest.mark.parametrize('version, expected_output', [
    ('11\\.00\\.00', True),
    ('1\\.0\\.0', True),
    ('1\\.0', True),
    ('1', False),
    ('\\.1\\.0', False),
    ('1\\.0\\.', False),
    ('1\\.\\.0', False),
    ('\\.1\\.0\\.', False),
])
def test_is_valid_dotted_version(version, expected_output):
    assert lookup.is_valid_dotted_version(version) == expected_output


@pytest.mark.parametrize('target_values, search_word, expected', [
    (['1\\.2\\.3', '2\\.2\\.2', '4\\.5\\.6'], '2\\.2\\.2', '1\\.2\\.3'),
    (['1\\.1\\.1', '1\\.2\\.3', '4\\.5\\.6'], '1\\.1\\.1', '1\\.2\\.3'),
    (['1\\.2\\.3', '4\\.5\\.6', '7\\.8\\.9'], '7\\.8\\.9', '4\\.5\\.6')
])
def test_find_next_closest_version(target_values, search_word, expected):
    assert lookup.find_next_closest_version(sorted_version_list=target_values, requested_version=search_word) == expected


def test_find_matching_cpe_product():
    assert SORT_CPE_MATCHES_OUTPUT == lookup.find_matching_cpe_product(MATCHED_CPE, VERSION_SEARCH_TERM)


@pytest.mark.parametrize('term, expected_output', [
    ('mircosoft', True),
    ('microsof', True),
    ('microso', True),
    ('ircosof', False),
])
def test_terms_match(term, expected_output):
    assert lookup.terms_match(term, 'microsoft') == expected_output


@pytest.mark.parametrize('word_list, remaining_words, expected_output', [
    (['aaaa', 'bbbb', 'cccc', 'dddd', 'eeee', 'ffff', 'gggg'], ['cccc', 'dddd', 'eeee'], True),
    (['abcde', 'ghkl'], ['abcdef', 'ghijkl'], True),
    (['abcde', 'ghkl'], ['abcdef', 'ghijklmnop'], False)
])
def test_word_is_in_word_list(word_list, remaining_words, expected_output):
    assert lookup.word_sequence_is_in_word_list(word_list, remaining_words) == expected_output


@pytest.mark.parametrize('word_list, remaining_words, expected_output', [
    (['abcde', 'ghkl'], ['abcdef', 'ghijkl'], True),
    (['abcde', 'ghkl'], ['abcdef', 'ghijklmnop'], False)
])
def test_remaining_words_present(word_list, remaining_words, expected_output):
    assert lookup.remaining_words_present(word_list, remaining_words) == expected_output


@pytest.mark.parametrize('word_list, expected_output', [
    ('bla bla microsoft windows 8 bla', True),
    ('bla bla microsoft windows', False),
    ('bla bla mirosoft windos 7 bla', True),
    ('bla bla microsoft corporation windows 8 bla', True),
    ('bla bla microsoft corporation corp inc windows 8 bla', False),
    ('bla bla microsoft windows 8', True),
    ('bla bla microsoft windows home 8 bla', False),
])
def test_product_is_mentioned(word_list, expected_output):
    assert lookup.product_is_mentioned_in_summary(SORT_CPE_MATCHES_OUTPUT, word_list) == expected_output


def test_match_cpe(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DatabaseInterface, 'fetch_multiple', lambda *_, **__: CPE_DATABASE_OUTPUT)
        actual_match = list(lookup.match_cpe(DatabaseInterface, PRODUCT_SEARCH_TERMS))
        assert all(entry in actual_match for entry in MATCHED_CPE)


def test_search_cve(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DatabaseInterface, 'fetch_multiple', lambda *_, **__: CPE_CVE_OUTPUT)
        actual_match = list(lookup.search_cve(DatabaseInterface, SORT_CPE_MATCHES_OUTPUT))
        assert sorted(MATCHED_CVE) == sorted(actual_match)


def test_search_cve_summary(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DatabaseInterface, 'fetch_multiple', lambda *_, **__: SUMMARY_OUTPUT)
        MATCHED_SUMMARY.sort()
        actual_match = list(lookup.search_cve_summary(DatabaseInterface, SORT_CPE_MATCHES_OUTPUT))
        actual_match.sort()
        assert MATCHED_SUMMARY == actual_match


class MockAdmin:
    def register_plugin(self, name, administrator):
        pass


@pytest.fixture(scope='function')
def test_config():
    return get_config_for_testing()


@pytest.fixture(scope='function')
def stub_plugin(test_config, monkeypatch):
    monkeypatch.setattr('plugins.base.BasePlugin._sync_view', lambda self, plugin_path: None)
    return lookup.AnalysisPlugin(MockAdmin(), test_config, offline_testing=True)


def test_process_object(stub_plugin):
    TEST_FW.processed_analysis['software_components'] = SOFTWARE_COMPONENTS_ANALYSIS_RESULT
    lookup.MAX_LEVENSHTEIN_DISTANCE = 0
    try:
        result = stub_plugin.process_object(TEST_FW).processed_analysis['cve_lookup']
        assert 'Dnsmasq 2.40 (CRITICAL)' in result['summary']
        assert 'Dnsmasq 2.40' in result['cve_results']
        assert 'CVE-2013-0198' in result['cve_results']['Dnsmasq 2.40']
    finally:
        lookup.MAX_LEVENSHTEIN_DISTANCE = 3


@pytest.mark.parametrize('cve_score, should_be_tagged', [('9.9', True), ('5.5', False)])
def test_add_tags(stub_plugin, cve_score, should_be_tagged):
    TEST_FW.processed_analysis['cve_lookup'] = {}
    cve_results = {'component': {'cve_id': {'score2': cve_score, 'score3': 'N/A'}}}
    stub_plugin.add_tags(cve_results, TEST_FW)
    if should_be_tagged:
        assert 'tags' in TEST_FW.processed_analysis['cve_lookup']
        tags = TEST_FW.processed_analysis['cve_lookup']['tags']
        assert 'CVE' in tags and tags['CVE']['value'] == 'critical CVE'
    else:
        assert 'tags' not in TEST_FW.processed_analysis['cve_lookup']


@pytest.mark.parametrize(
    'cpe_version, cve_version, version_start_including, version_start_excluding, version_end_including, version_end_excluding, expected_output',
    [
        ('1', '1', '', '', '', '', True),
        ('1', '2', '', '', '', '', False),
        ('1.2.3', '1.2.3', '', '', '', '', True),
        ('1.2.3', '1.8.3', '', '', '', '', False),
        ('v1.2a', 'v1.2a', '', '', '', '', True),
        ('v1.2a', 'v1.2b', '', '', '', '', False),
        ('1', 'ANY', '', '', '', '', True),
        ('1', 'N/A', '', '', '', '', True),
        ('1.2', 'ANY', '1.1', '', '', '', True),
        ('1.2', 'ANY', '1.2', '', '', '', True),
        ('1.1', 'ANY', '1.2', '', '', '', False),
        ('1.2', 'ANY', '', '1.1', '', '', True),
        ('1.2', 'ANY', '', '1.2', '', '', False),
        ('1.1', 'ANY', '', '1.2', '', '', False),
        ('1.2', 'ANY', '', '', '1.1', '', False),
        ('1.2', 'ANY', '', '', '1.2', '', True),
        ('1.1', 'ANY', '', '', '1.2', '', True),
        ('1.2', 'ANY', '', '', '', '1.1', False),
        ('1.2', 'ANY', '', '', '', '1.2', False),
        ('1.1', 'ANY', '', '', '', '1.2', True),
        ('1.0', 'ANY', '', '1.1', '', '1.3', False),
        ('1.1', 'ANY', '', '1.1', '', '1.3', False),
        ('1.2', 'ANY', '', '1.1', '', '1.3', True),
        ('1.3', 'ANY', '', '1.1', '', '1.3', False),
        ('1.4', 'ANY', '', '1.1', '', '1.3', False),
        ('1.0', 'ANY', '1.1', '', '1.3', '', False),
        ('1.1', 'ANY', '1.1', '', '1.3', '', True),
        ('1.2', 'ANY', '1.1', '', '1.3', '', True),
        ('1.3', 'ANY', '1.1', '', '1.3', '', True),
        ('1.4', 'ANY', '1.1', '', '1.3', '', False),
        ('$%&fööbar,.-', '1.2.3', '', '', '', '', False),
        ('v1.1a', 'ANY', 'v1.1a', '', 'v1.1a', '', True),
        ('v1.1b', 'ANY', '', 'v1.1a', '', 'v1.1c', True),
        ('v1.1a', 'ANY', '', 'v1.1b', '', 'v1.1c', False),
        ('1.1-r2345', 'ANY', '', '1.1-r1234', '', '1.1-r3456', True),
    ]
)
def test_versions_match(cpe_version: str, cve_version: str, version_start_including: str, version_start_excluding: str,
                        version_end_including: str, version_end_excluding: str, expected_output: bool):
    cve_entry = lookup.CveDbEntry(None, None, None, cve_version, None, None, version_start_including,
                                  version_start_excluding, version_end_including, version_end_excluding)
    assert lookup.versions_match(cpe_version, cve_entry) == expected_output


@pytest.mark.parametrize('version, version_start_including, version_start_excluding, version_end_including, version_end_excluding, expected_output', [
    ('1.2', '', '', '', '', '1.2'),
    ('ANY', '', '', '', '', 'ANY'),
    ('N/A', '', '', '', '', 'N/A'),
    ('ANY', '1.2', '', '', '', '1.2 ≤ version'),
    ('ANY', '', '1.2', '', '', '1.2 < version'),
    ('ANY', '', '', '1.2', '', 'version ≤ 1.2'),
    ('ANY', '', '', '', '1.2', 'version < 1.2'),
    ('ANY', '1.1', '', '1.2', '', '1.1 ≤ version ≤ 1.2'),
    ('ANY', '', '1.1', '', '1.2', '1.1 < version < 1.2'),
])
def test_build_version_string(version: str, version_start_including: str, version_start_excluding: str,
                              version_end_including: str, version_end_excluding: str, expected_output: str):
    cve_entry = lookup.CveDbEntry(None, None, None, version, None, None, version_start_including,
                                  version_start_excluding, version_end_including, version_end_excluding)
    assert lookup.build_version_string(cve_entry) == expected_output


@pytest.mark.parametrize('cve_results_dict, expected_output', [
    ({}, []),
    ({'component': {'cve_id': {'score2': '6.4', 'score3': 'N/A'}}}, ['component']),
    ({'component': {'cve_id': {'score2': '9.4', 'score3': 'N/A'}}}, ['component (CRITICAL)']),
    ({'component': {'cve_id': {'score2': '1.1', 'score3': '9.9'}, 'cve_id2': {'score2': '1.1', 'score3': '0.0'}}}, ['component (CRITICAL)']),
])
def test_create_summary(cve_results_dict, expected_output, stub_plugin):
    assert stub_plugin._create_summary(cve_results_dict) == expected_output  # pylint: disable=protected-access

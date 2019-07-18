from collections import namedtuple
from os import remove

import pytest
from helperFunctions.config import get_config_for_testing
from test.common_helper import TEST_FW

from ..code import vuln_lookup_plugin as lookup
from ..internal.meta import DB, unbinding

# pylint: disable=redefined-outer-name

USER_INPUT = {'vendor': 'Microsoft', 'product': 'Windows 7', 'version': '1.2.5'}

PRODUCT = namedtuple('PRODUCT', 'vendor_name product_name version_number')
MATCHED_CPE = [PRODUCT('microsoft', 'windows_8', '1\\.2\\.5'), PRODUCT('microsoft', 'windows_7', '1\\.3\\.1'),
               PRODUCT('mircosof', 'windows_7', '0\\.7')]
PRODUCT_NAME = 'windows 7'
MATCHED_CVE = ['CVE-1234-0010', 'CVE-1234-0011']
CPE_CVE_OUTPUT = [('CVE-1234-0008', 'microsoft', 'server_2013', '2013'),
                  ('CVE-1234-0009', 'mircosof', 'windows_7', '0\\.7'),
                  ('CVE-1234-0010', 'microsoft', 'windows_8', '1\\.2\\.5'),
                  ('CVE-1234-0011', 'microsoft', 'windows_7', '1\\.3\\.1'),
                  ('CVE-1234-0012', 'linux', 'linux_kernel', '2\\.2.\\3')]

MATCHED_SUMMARY = ['CVE-1234-0005', 'CVE-1234-0006', 'CVE-1234-0007']
SUMMARY_OUTPUT = [('CVE-1234-0001', 'Attacker gains remote access'),
                  ('CVE-1234-0002', 'Attacker gains remote access to microsoft windows'),
                  ('CVE-1234-0003', 'Attacker gains remote access to microsoft server 2018'),
                  ('CVE-1234-0004', 'Attacker gains remote access to microsoft windows 2018'),
                  ('CVE-1234-0005', 'Attacker gains remote access to microsoft windows 8'),
                  ('CVE-1234-0006', 'Attacker gains remote access to microsoft windows 7'),
                  ('CVE-1234-0007', 'Attacker gains remote access to microsoft corporation windows 7')]

PRODUCT_SEARCH_TERMS = ['windows', 'windows_7']
VERSION_SEARCH_TERM = '1\\.2\\.5'
CPE_DATABASE_OUTPUT = [('microsoft', 'server_2013', '2013'),
                       ('mircosof', 'windows_7', '0\\.7'),
                       ('microsoft', 'windows_8', '1\\.2\\.5'),
                       ('microsoft', 'windows_7', '1\\.3\\.1'),
                       ('linux', 'linux_kernel', '2\\.2.\\3')]

TERMS_MATCH_INPUT = ['mircosoft', 'microsof', 'microso', 'ircosof']
MATCHING_TERM = 'microsoft'
TERMS_MATCH_OUTPUT = [True, True, True, False]
REMAINING_WORDS_INPUT = ['abcdef', 'ghijkl']
REMAINING_WORDS_INPUT_2 = ['abcdef', 'ghijklmnop']
WORDS_INPUT = ['abcde', 'ghkl']
SUMMARY_INPUT = ''

VALID_DOTTED_VERSION_INPUT = ['11\\.00\\.00', '1\\.0\\.0', '1\\.0', '1', '\\.1\\.0', '1\\.0\\.', '1\\.\\.0', '\\.1\\.0\\.']
VALID_DOTTED_VERSION_OUTPUT = [True, True, True, False, False, False, False, False]

HASINDEX_INPUT = ['1\\.0 3', '1\\.0 1', '1\\.0 0']
HASINDEX_OUTPUT = [False, True, True]

WORDLIST_LONGER_THAN_SEQUENCE_INPUT = [[['', '', ''], ['', '']], [['', ''], ['', '', '']], [['', ''], ['', '']]]
WORDLIST_LONGER_THAN_SEQUENCE_OUTPUT = [True, False, True]


SORT_CPE_MATCHES_OUTPUT = PRODUCT('microsoft', 'windows_8', '1\\.2\\.5')
PRODUCT_IS_IN_WORDLIST_INPUT = [{'Product': SORT_CPE_MATCHES_OUTPUT, 'Wordlist': ['bla', 'bla', 'microsoft', 'windows', '8', 'bla']},
                                {'Product': SORT_CPE_MATCHES_OUTPUT, 'Wordlist': ['bla', 'bla', 'microsoft', 'windows']},
                                {'Product': SORT_CPE_MATCHES_OUTPUT, 'Wordlist': ['bla', 'bla', 'mirosoft', 'windos', '7', 'bla']},
                                {'Product': SORT_CPE_MATCHES_OUTPUT, 'Wordlist': ['bla', 'bla', 'microsoft', 'corporation', 'windows', '8', 'bla']},
                                {'Product': SORT_CPE_MATCHES_OUTPUT, 'Wordlist': ['bla', 'bla', 'microsoft', 'corporation', 'corp', 'inc', 'windows', '8', 'bla']},
                                {'Product': SORT_CPE_MATCHES_OUTPUT, 'Wordlist': ['bla', 'bla', 'microsoft', 'windows', '8']},
                                {'Product': SORT_CPE_MATCHES_OUTPUT, 'Wordlist': ['bla', 'bla', 'microsoft', 'windows', 'home', '8', 'bla']}]
PRODUCT_IS_IN_WORDLIST_OUTPUT = [True, False, True, True, False, True, False]

SORT_DOTTED_VERSIONS_INPUT = [{'cpe_matches': [PRODUCT('microsoft', 'windows_7', '2\\.3\\.5'), PRODUCT('microsoft', 'windows_7', '2\\.2\\.2'),
                                               PRODUCT('microsoft', 'windows_7', '3\\.2\\.5')], 'version': VERSION_SEARCH_TERM},
                              {'cpe_matches': [PRODUCT('microsoft', 'windows_7', '1\\.2\\.7'), PRODUCT('microsoft', 'windows_7', '1\\.2\\.6'),
                                               PRODUCT('microsoft', 'windows_7', '2\\.2\\.5')], 'version': VERSION_SEARCH_TERM}]
SORT_DOTTED_VERSIONS_OUTPUT = [PRODUCT('microsoft', 'windows_7', '2\\.2\\.2'), PRODUCT('microsoft', 'windows_7', '1\\.2\\.7')]


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    yield None
    try:
        remove('test.db')
    except OSError:
        pass


def test_generate_search_terms():
    assert PRODUCT_SEARCH_TERMS == unbinding(lookup.generate_search_terms(PRODUCT_NAME))


def test_sort_cpe_matches():
    assert SORT_CPE_MATCHES_OUTPUT == lookup.sort_cpe_matches(MATCHED_CPE, VERSION_SEARCH_TERM)


def test_sort_dotted_versions():
    for index, version_input in enumerate(SORT_DOTTED_VERSIONS_INPUT):
        assert SORT_DOTTED_VERSIONS_OUTPUT[index] == lookup.sort_dotted_versions(version_input['cpe_matches'], version_input['version'])[0]


def test_is_valid_dotted_version():
    for index in range(8):
        assert VALID_DOTTED_VERSION_OUTPUT[index] == bool(lookup.is_valid_dotted_version(VALID_DOTTED_VERSION_INPUT[index]))


def test_has_index():
    for index, pair in enumerate(HASINDEX_INPUT):
        string, given_index = pair.split(' ')
        assert HASINDEX_OUTPUT[index] == lookup.has_index(string, int(given_index))


def test_terms_match():
    assert TERMS_MATCH_OUTPUT == [lookup.terms_match(TERMS_MATCH_INPUT[i], MATCHING_TERM)
                                  for i in range(len(TERMS_MATCH_INPUT))]


def test_word_is_in_wordlist():
    assert lookup.remaining_words_present(WORDS_INPUT, REMAINING_WORDS_INPUT) is True
    assert lookup.remaining_words_present(WORDS_INPUT, REMAINING_WORDS_INPUT_2) is False


def test_remaining_words_present():
    assert lookup.remaining_words_present(WORDS_INPUT, REMAINING_WORDS_INPUT) is True
    assert lookup.remaining_words_present(WORDS_INPUT, REMAINING_WORDS_INPUT_2) is False


def test_product_is_in_wordlist():
    for index, parameter in enumerate(PRODUCT_IS_IN_WORDLIST_INPUT):
        assert PRODUCT_IS_IN_WORDLIST_OUTPUT[index] == lookup.product_is_in_wordlist(parameter['Product'], parameter['Wordlist'])


def test_wordlist_longer_than_sequence():
    for index, pair in enumerate(WORDLIST_LONGER_THAN_SEQUENCE_INPUT):
        wordlist, sequence = pair[0], pair[1]
        assert WORDLIST_LONGER_THAN_SEQUENCE_OUTPUT[index] == lookup.wordlist_longer_than_sequence(wordlist, sequence)


def test_match_cpe(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DB, 'select_query', lambda *_, **__: CPE_DATABASE_OUTPUT)
        MATCHED_CPE.sort()
        actual_match = list(lookup.match_cpe(DB, PRODUCT_SEARCH_TERMS))
        actual_match.sort()
        assert MATCHED_CPE == actual_match


def test_search_cve(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DB, 'select_query', lambda *_, **__: CPE_CVE_OUTPUT)
        MATCHED_CVE.sort()
        actual_match = list(lookup.search_cve(DB, SORT_CPE_MATCHES_OUTPUT))
        actual_match.sort()
        assert MATCHED_CVE == actual_match


def test_search_cve_summary(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DB, 'select_query', lambda *_, **__: SUMMARY_OUTPUT)
        MATCHED_SUMMARY.sort()
        actual_match = list(lookup.search_cve_summary(DB, SORT_CPE_MATCHES_OUTPUT))
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
    TEST_FW.processed_analysis['software_components'] = {
        'dnsmasq': {
            'meta': {
                'software_name': 'Dnsmasq',
                'version': [
                    '2.40'
                ]
            }
        },
        'OpenSSL': {
            'matches': True,
            'meta': {
                'description': 'SSL library',
                'open_source': True,
                'software_name': 'OpenSSL',
                'version': [
                    ''
                ],
                'website': 'https://www.openssl.org'
            },
            'rule': 'OpenSSL',
            'strings': [
                [
                    7194,
                    '$a',
                    'T1BFTlNTTA=='
                ],
            ]
        },
        'analysis_date': 1563453634.37708,
        'plugin_version': '0.3.2',
        'summary': [
            'OpenSSL ',
            'Dnsmasq 2.40'
        ],
        'system_version': '3.7.1_1560435912',
    }
    result = stub_plugin.process_object(TEST_FW).processed_analysis['cve_lookup']
    assert 'CVE-2018-1000010' in result['summary']

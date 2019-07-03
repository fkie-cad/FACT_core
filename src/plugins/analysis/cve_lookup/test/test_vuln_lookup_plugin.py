from os import remove
from collections import namedtuple

import pytest

from ..code import vuln_lookup_plugin as lookup
from ..internal.meta import DB, unbinding

USER_INPUT = {'vendor': 'Microsoft', 'product': 'Windows 7', 'version': '1.2.5'}

PRODUCT = namedtuple('PRODUCT', 'vendor_name product_name version_number')
TEST_PRODUCT = PRODUCT('microsoft', 'windows 7', '1\\.2\\.5')
PRODUCT = 'windows 7'
MATCHED_CVE = ['CVE-1234-0009', 'CVE-1234-0010', 'CVE-1234-0011']
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

PRODUCT_SEARCH_TERMS = ['windows', 'windows_7', '7']
VERSION_SEARCH_TERM = '1\\.2\\.5'
MATCHED_CPE = [('microsoft', 'windows_8', '1\\.2\\.5'), ('microsoft', 'windows_7', '1\\.3\\.1'),
               ('mircosof', 'windows_7', '0\\.7')]
CPE_OUTPUT = [('microsoft', 'server_2013', '2013'),
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


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    yield None
    try:
        remove('test.db')
    except OSError:
        pass


def test_generate_search_terms():
    assert PRODUCT_SEARCH_TERMS == unbinding(lookup.generate_search_terms(PRODUCT))


def test_sort_cpe_matches():
    pass


def test_sort_dotted_versions():
    pass


def test_is_valid_dotted_version():
    pass


def test_hasindex():
    pass


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
    pass


def test_wordlist_longer_than_word():
    pass


def test_match_cpe(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DB, 'select_query', lambda *_, **__: CPE_OUTPUT)
        assert MATCHED_CPE.sort() == list(lookup.match_cpe(DB, PRODUCT_SEARCH_TERMS)).sort()


def test_search_cve(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DB, 'select_query', lambda *_, **__: CPE_CVE_OUTPUT)
        assert MATCHED_CVE.sort() == list(lookup.search_cve(DB, TEST_PRODUCT)).sort()


def test_search_cve_summary(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DB, 'select_query', lambda *_, **__: SUMMARY_OUTPUT)
        assert MATCHED_SUMMARY.sort() == list(lookup.search_cve_summary(DB, TEST_PRODUCT)).sort()

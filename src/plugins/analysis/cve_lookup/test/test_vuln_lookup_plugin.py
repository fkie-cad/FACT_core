import os

import pytest

from ..code import vuln_lookup_plugin as lookup
from ..internal.meta import DB
from ..internal.meta import get_meta

METADATA = get_meta()
USER_INPUT = {'vendor': 'Microsoft', 'product': 'Windows 7', 'version': '1.2.5'}

TEST_PRODUCT = lookup.Product('microsoft', 'windows 7', '1\\.2\\.5')
PRODUCT = 'windows 7'
VERSION = '1\\.2\\.5'
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
MATCHED_CPE = ('microsoft', 'windows_8', '1\\.2\\.5')
CPE_OUTPUT = [('microsoft', 'server_2013', '2013'),
              ('mircosof', 'windows_7', '0\\.7'),
              ('microsoft', 'windows_8', '1\\.2\\.5'),
              ('microsoft', 'windows_7', '1\\.3\\.1'),
              ('linux', 'linux_kernel', '2\\.2.\\3')]


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    yield None
    try:
        os.remove('test.db')
    except OSError:
        pass


def test_generate_search_terms():
    assert (PRODUCT_SEARCH_TERMS, VERSION_SEARCH_TERM) == lookup.generate_search_terms(PRODUCT, VERSION)


def test_cpe_matching(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DB, 'select_query', lambda *_, **__: CPE_OUTPUT)
        assert MATCHED_CPE == lookup.cpe_matching(DB, METADATA, PRODUCT_SEARCH_TERMS, VERSION_SEARCH_TERM)


def test_cpe_cve_search(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DB, 'select_query', lambda *_, **__: CPE_CVE_OUTPUT)
        assert MATCHED_CVE.sort() == lookup.cve_cpe_search(DB, METADATA, TEST_PRODUCT).sort()


def test_cve_summary_search(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(DB, 'select_query', lambda *_, **__: SUMMARY_OUTPUT)
        assert MATCHED_SUMMARY.sort() == lookup.cve_summary_search(DB, METADATA, TEST_PRODUCT).sort()

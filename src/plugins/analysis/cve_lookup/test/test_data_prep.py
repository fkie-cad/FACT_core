import sys
from glob import glob
from os import remove
from pathlib import Path

import pytest

try:
    from internal import data_prep as dp
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    import data_prep as dp

# contains a NODES list from the CVE 2012-0010 which serves as input for iterate_nodes()
NODES = [{'operator': 'AND', 'children': [{'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri':
                                                                            'cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*'}]},
                                          {'operator': 'OR', 'cpe_match': [{'vulnerable': False,
                                                                            'cpe23Uri': 'cpe:2.3:o: microsoft:windows_'
                                                                                        'xp:*:sp3:*:*:*:*:*:*'},
                                                                           {'vulnerable': False,
                                                                            'cpe23Uri': 'cpe:2.3:o:microsoft:windows_xp'
                                                                                        ':-:sp2:x64:*:*:*:*:*'}]}]},
         {'operator': 'AND', 'children': [{'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri':
                                                                            'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*'}]},
                                          {'operator': 'OR', 'cpe_match': [{'vulnerable': False,
                                                                            'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:'
                                                                                        '*:*:x64:*:*:*:*:*'},
                                                                           {'vulnerable': False,
                                                                            'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:'
                                                                                        '*:*:x86:*:*:*:*:*'},
                                                                           {'vulnerable': False,
                                                                            'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:'
                                                                                        '*:sp1:x64:*:*:*:*:*'},
                                                                           {'vulnerable': False,
                                                                            'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:'
                                                                                        '*:sp1:x86:*:*:*:*:*'},
                                                                           {'vulnerable': False,
                                                                            'cpe23Uri': 'cpe:2.3:o:microsoft:windows_'
                                                                                        'vista:*:sp2:*:*:*:*:*:*'},
                                                                           {'vulnerable': False,
                                                                            'cpe23Uri': 'cpe:2.3:o:microsoft:windows_'
                                                                                        'vista:*:sp2:x64:*:*:*:*:*'},
                                                                           {'vulnerable': False,
                                                                            'cpe23Uri': 'cpe:2.3:o:microsoft:windows_xp'
                                                                                        ':*:sp3:*:*:*:*:*:*'}]}]},
         {'operator': 'AND', 'children': [{'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri':
                                                                            'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*'}]},
                                          {'operator': 'OR', 'cpe_match': [{'vulnerable': False, 'cpe23Uri':
                                                                            'cpe:2.3:o:microsoft:windows_vista:*:sp2:*:'
                                                                            '*:*:*:*:*'},
                                                                           {'vulnerable': False, 'cpe23Uri':
                                                                            'cpe:2.3:o:microsoft:windows_vista:*:sp2:'
                                                                            'x64:*:*:*:*:*'},
                                                                           {'vulnerable': False, 'cpe23Uri':
                                                                            'cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*'
                                                                            ':*:*:*'},
                                                                           {'vulnerable': False, 'cpe23Uri':
                                                                            'cpe:2.3:o:microsoft:windows_xp:-:sp2:x64:*'
                                                                            ':*:*:*:*'}]}]},
         {'operator': 'AND', 'children': [{'operator': 'OR', 'cpe_match': [{'vulnerable': True, 'cpe23Uri':
                                                                            'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*'}]},
                                          {'operator': 'OR', 'cpe_match':
                                           [{'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:*:'
                                                                              'x64:*:*:*:*:*'},
                                            {'vulnerable': False,
                                             'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:*:x86:*:*:*:*:*'},
                                            {'vulnerable': False,
                                             'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:sp1:x64:*:*:*:*:*'},
                                            {'vulnerable': False,
                                             'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:sp1:x86:*:*:*:*:*'},
                                            {'vulnerable': False,
                                             'cpe23Uri': 'cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*'},
                                            {'vulnerable': False,
                                             'cpe23Uri': 'cpe:2.3:o:microsoft:windows_vista:*:sp2:x64:*:*:*:*:*'},
                                            {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_xp:*:sp3'
                                                                              ':*:*:*:*:*:*'}]}]}]
# contain the expected result from the extract_cve function
CVE_CPE_LIST = ['CVE-2012-0001', 'cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_7:-:sp1:x64:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_7:-:sp1:x86:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x32:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x64:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_server_2008:-:sp2:itanium:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_server_2008:r2:*:itanium:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_server_2008:r2:*:x64:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:itanium:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:x64:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_vista:*:sp2:x64:*:*:*:*:*',
                'cpe:2.3:o:microsoft:windows_xp:*:sp2:professional_x64:*:*:*:*:*',
                'CVE-2018-0010', 'cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*', 'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*',
                'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*', 'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*']

SUMMARY_EXTRACT_LIST = ['CVE-2018-20229', 'GitLab Community and Enterprise Edition before 11.3.14, '
                                          '11.4.x before 11.4.12, and 11.5.x before 11.5.5 allows Directory Traversal.',
                        'CVE-2018-8825', 'Google TensorFlow 1.7 and below is affected by: Buffer Overflow. '
                                         'The impact is: execute arbitrary code (local).']
# contains the expected result from the iterate_node function
NODE_LIST = ['cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*', 'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*',
             'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*', 'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*']
# contains the expected CPE format string result from the extract_cpe function
CPE_EXTRACT_LIST = ['cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
                    'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*', 'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
                    'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*', 'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*']

# contain input and expected results of the setup_cve_format function
CVE_LIST = ['CVE-2012-0001', 'cpe:2.3:a:\\$0.99_kindle_bo\\:oks_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
            'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*', 'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
            'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*', 'CVE-2012-0002',
            'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*']
SUMMARY_LIST = ['CVE-2018-20229', 'GitLab Community and Enterprise Edition before 11.3.14, 11.4.x before 11.4.12, '
                                  'and 11.5.x before 11.5.5 allows Directory Traversal.', 'CVE-2018-0010',
                'Microsoft Internet Explorer 6 through 9 does not properly perform copy-and-paste operations, '
                'which allows user-assisted remote attackers to read content from a different (1) domain or (2) '
                'zone via a crafted web site, aka \'Copy and Paste Information Disclosure Vulnerability.\'']
CVE_TABLE = [('CVE-2012-0001', '2012',
              'cpe:2.3:a:\\$0.99_kindle_bo\\:oks_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*', 'a',
              '\\$0\\.99_kindle_bo\\:oks_project', '\\$0\\.99_kindle_books', '6', 'ANY', 'ANY', 'ANY', 'ANY',
              'android', 'ANY', 'ANY'),
             ('CVE-2012-0001', '2012', 'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*', 'a', '1000guess',
              '1000_guess', 'NA', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
             ('CVE-2012-0001', '2012', 'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms',
              '0\\.7', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
             ('CVE-2012-0001', '2012', 'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms',
              '1\\.2\\.5', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
             ('CVE-2012-0002', '2012', 'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms',
              '1\\.3\\.1', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY')]
SUMMARY_TABLE = [('CVE-2018-20229', '2018', 'GitLab Community and Enterprise Edition before 11.3.14, 11.4.x before '
                                            '11.4.12, and 11.5.x before 11.5.5 allows Directory Traversal.'),
                 ('CVE-2018-0010', '2018', 'Microsoft Internet Explorer 6 through 9 does not properly perform '
                                           'copy-and-paste operations, which allows user-assisted remote attackers '
                                           'to read content from a different (1) domain or (2) zone via a crafted '
                                           'web site, aka \'Copy and Paste Information Disclosure Vulnerability.\'')]
# contain input and expected results of the setup_cpe_format function
CPE_LIST = ['cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
            'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*', 'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
            'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*', 'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*']
CPE_TABLE = [('cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*', 'a',
              '\\$0\\.99_kindle_books_project', '\\$0\\.99_kindle_books', '6', 'ANY', 'ANY', 'ANY', 'ANY',
              'android', 'ANY', 'ANY'),
             ('cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*', 'a', '1000guess', '1000_guess', 'NA', 'ANY', 'ANY',
              'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
             ('cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '0\\.7', 'ANY', 'ANY',
              'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
             ('cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '1\\.2\\.5', 'ANY',
              'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
             ('cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '1\\.3\\.1', 'ANY',
              'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY')]

GET_CVE_LINKS_EXPECTED_OUTPUT = list()
for i in range(2002, 2020):
    GET_CVE_LINKS_EXPECTED_OUTPUT.append(dp.CVE_URL.format(i))

DOWNLOAD_DATA_YEAR_INPUT = [2018, 2019]

DOWNLOAD_CPE_EXPECTED = ['official-cpe-dictionary_v2.3.xml']

DOWNLOAD_CVE_EXPECTED = ['nvdcve-1.0-2018.json', 'nvdcve-1.0-2019.json']

DOWNLOAD_UPDATE_EXPECTED = ['nvdcve-1.0-modified.json']

DOWNLOAD_DATA_EXPECTED_OUTPUT = ['official-cpe-dictionary_v2.3.xml', 'nvdcve-1.0-modified.json']

ALL_CVE_URLS = ['nvdcve-1.0-2017.json', 'nvdcve-1.0-2018.json', 'nvdcve-1.0-2019.json', 'nvdcve-1.0-modified.json']
SELECT_CVE_URLS_EXPECTED_OUTPUT = ['nvdcve-1.0-2018.json', 'nvdcve-1.0-2019.json']


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    yield None
    try:
        remove('official-cpe-dictionary_v2.3.xml')
        for file in glob('nvdcve-1.0-*.json'):
            remove(file)
    except OSError:
        pass


def test_get_cve_links():
    assert GET_CVE_LINKS_EXPECTED_OUTPUT == dp.get_cve_links(dp.CVE_URL)


def test_download_cve():
    dp.download_cve(years=DOWNLOAD_DATA_YEAR_INPUT, download_path='.', update=False)
    assert set(DOWNLOAD_CVE_EXPECTED) == set(glob('nvdcve-1.0-*.json'))
    dp.download_cve(years=DOWNLOAD_DATA_YEAR_INPUT, download_path='.', update=True)
    assert DOWNLOAD_UPDATE_EXPECTED == glob('nvdcve-1.0-modified.json')


def test_download_cpe():
    dp.download_cpe(download_path='.')
    assert DOWNLOAD_CPE_EXPECTED == glob('official-cpe-dictionary_v2.3.xml')


def test_iterate_urls():
    dp.iterate_urls(['https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip',
                     'https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip'], '.')
    downloaded_files = list()
    downloaded_files.extend(glob('official-cpe-dictionary_v2.3.xml'))
    downloaded_files.extend(glob('nvdcve-1.0-modified.json'))
    assert set(DOWNLOAD_DATA_EXPECTED_OUTPUT) == set(downloaded_files)


def test_extract_data_from_cve():
    root = dp.json.loads(Path(str(Path(__file__).parent.parent) + '/test/test_resources/test_cve_extract.json').read_text())
    cve_data, summary_data = dp.extract_data_from_cve(root)
    CVE_CPE_LIST.sort()
    SUMMARY_EXTRACT_LIST.sort()
    cve_data.sort()
    summary_data.sort()
    assert CVE_CPE_LIST == cve_data
    assert SUMMARY_EXTRACT_LIST == summary_data


def test_extract_cve(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(dp.Path, 'read_text', lambda *_, **__: '{"foo": "bar"}')
        monkey.setattr(dp, 'extract_data_from_cve', lambda root: root)
        assert dp.extract_cve('') == {'foo': 'bar'}


def test_iterate_nodes():
    test_node_list = list()
    assert NODE_LIST == dp.iterate_nodes(NODES, test_node_list)


def test_extract_cpe():
    assert CPE_EXTRACT_LIST == dp.extract_cpe(str(Path(__file__).parent.parent) + '/test/test_resources/test_cpe_extract.xml')


def test_setup_cve_feeds_table():
    cve_result = dp.setup_cve_feeds_table(CVE_LIST)
    cve_result.sort()
    CVE_TABLE.sort()
    assert CVE_TABLE == cve_result


def test_setup_cve_summary_table():
    summary_result = dp.setup_cve_summary_table(SUMMARY_LIST)
    summary_result.sort()
    SUMMARY_TABLE.sort()
    assert SUMMARY_TABLE == summary_result


def test_setup_cpe_table():
    assert CPE_TABLE == dp.setup_cpe_table(CPE_LIST)

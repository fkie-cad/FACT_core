import sys
from datetime import datetime
from glob import glob
from os import remove
from pathlib import Path

import pytest

try:
    from ..internal import data_parsing
    from ..internal.helper_functions import CveEntry, CveSummaryEntry
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    import data_parsing
    from helper_functions import CveEntry, CveSummaryEntry

# contains a NODES list from the CVE 2012-0010 which serves as input for iterate_nodes()
NODES = [
    {
        'operator': 'AND',
        'children': [
            {
                'operator': 'OR',
                'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*'}],
            },
            {
                'operator': 'OR',
                'cpe_match': [
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o: microsoft:windows_xp:*:sp3:*:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_xp:-:sp2:x64:*:*:*:*:*'},
                ],
            },
        ],
    },
    {
        'operator': 'AND',
        'children': [
            {
                'operator': 'OR',
                'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*'}],
            },
            {
                'operator': 'OR',
                'cpe_match': [
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:*:x64:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:*:x86:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:sp1:x64:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:sp1:x86:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_vista:*:sp2:x64:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*'},
                ],
            },
        ],
    },
    {
        'operator': 'AND',
        'children': [
            {
                'operator': 'OR',
                'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*'}],
            },
            {
                'operator': 'OR',
                'cpe_match': [
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_vista:*:sp2:x64:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_xp:-:sp2:x64:*:*:*:*:*'},
                ],
            },
        ],
    },
    {
        'operator': 'AND',
        'children': [
            {
                'operator': 'OR',
                'cpe_match': [{'vulnerable': True, 'cpe23Uri': 'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*'}],
            },
            {
                'operator': 'OR',
                'cpe_match': [
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:*:x64:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:*:x86:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:sp1:x64:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_7:*:sp1:x86:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_vista:*:sp2:x64:*:*:*:*:*'},
                    {'vulnerable': False, 'cpe23Uri': 'cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*'},
                ],
            },
        ],
    },
]
# contain the expected result from the extract_cve function
CVE_CPE_LIST = [
    'cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*',
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
]

SUMMARY_EXTRACT_LIST = [
    'CVE-2018-20229',
    'GitLab Community and Enterprise Edition before 11.3.14, '
    '11.4.x before 11.4.12, and 11.5.x before 11.5.5 allows Directory Traversal.',
    'CVE-2018-8825',
    'Google TensorFlow 1.7 and below is affected by: Buffer Overflow. '
    'The impact is: execute arbitrary code (local).',
]
# contains the expected result from the iterate_node function
NODE_LIST = [
    'cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*',
    'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*',
]
# contains the expected CPE format string result from the extract_cpe function
CPE_EXTRACT_LIST = [
    'cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
    'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*',
    'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
    'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*',
    'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*',
]

DOWNLOAD_DATA_YEAR_INPUT = [2018, 2019]

DOWNLOAD_CVE_EXPECTED = ['nvdcve-1.0-2018.json', 'nvdcve-1.0-2019.json']

DOWNLOAD_UPDATE_EXPECTED = ['nvdcve-1.0-modified.json']

DOWNLOAD_DATA_EXPECTED_OUTPUT = [data_parsing.CPE_FILE, 'nvdcve-1.0-modified.json']

SELECT_CVE_URLS_EXPECTED_OUTPUT = ['nvdcve-1.0-2018.json', 'nvdcve-1.0-2019.json']


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    yield None
    try:
        remove(data_parsing.CPE_FILE)
        for file in glob('nvdcve-1.0-*.json'):
            remove(file)
    except OSError:
        pass


def test_get_cve_links():
    this_year = datetime.today().year
    expected_links = [data_parsing.CVE_URL.format(year) for year in range(2002, this_year + 1)]
    actual_links = data_parsing.get_cve_links(data_parsing.CVE_URL)
    assert len(actual_links) == this_year - 2001
    assert expected_links == actual_links


@pytest.mark.skip(reason='don\'t download each time')
def test_download_cve():
    data_parsing.download_cve(download_path='.', years=DOWNLOAD_DATA_YEAR_INPUT, update=False)
    assert set(DOWNLOAD_CVE_EXPECTED) == set(glob('nvdcve-1.0-*.json'))
    data_parsing.download_cve(download_path='.', years=DOWNLOAD_DATA_YEAR_INPUT, update=True)
    assert DOWNLOAD_UPDATE_EXPECTED == glob('nvdcve-1.0-modified.json')


@pytest.mark.skip(reason='don\'t download each time')
def test_download_cpe():
    data_parsing.download_cpe(download_path='.')
    assert Path(data_parsing.CPE_FILE).is_file()


@pytest.mark.skip(reason='don\'t download each time')
@pytest.mark.parametrize(
    'url, expected_file',
    [
        ('https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.zip', data_parsing.CPE_FILE),
        ('https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.zip', 'nvdcve-1.0-modified.json'),
    ],
)
def test_iterate_urls(url, expected_file):
    data_parsing.process_url(url, '.')
    assert Path(expected_file).is_file()


def test_extract_data_from_cve():
    raw_cve_data = data_parsing.json.loads((Path(__file__).parent / 'test_resources/test_cve_extract.json').read_text())
    cve_data, summary_data = data_parsing.extract_data_from_cve(raw_cve_data)
    assert len(cve_data) == 2
    assert len(summary_data) == 2
    assert all(isinstance(entry, CveEntry) for entry in cve_data)
    assert all(isinstance(entry, CveSummaryEntry) for entry in summary_data)
    assert any(entry.cve_id == 'CVE-2018-0010' for entry in cve_data)
    assert len(cve_data[0].cpe_list) == 14
    cpe_list = list(zip(*cve_data[0].cpe_list))[0]
    assert all(cpe in cpe_list for cpe in CVE_CPE_LIST)


def test_extract_cve(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(data_parsing.Path, 'read_text', lambda *_, **__: '{"foo": "bar"}')
        monkey.setattr(data_parsing, 'extract_data_from_cve', lambda root: root)
        assert data_parsing.extract_cve('') == {'foo': 'bar'}


def test_iterate_nodes():
    cpe_output = data_parsing.extract_cpe_data_from_cve(NODES)
    cpe_list = list(zip(*cpe_output))[0]
    assert sorted(NODE_LIST) == sorted(cpe_list)


def test_extract_cpe():
    assert CPE_EXTRACT_LIST == data_parsing.extract_cpe(
        str(Path(__file__).parent / 'test_resources/test_cpe_extract.xml')
    )

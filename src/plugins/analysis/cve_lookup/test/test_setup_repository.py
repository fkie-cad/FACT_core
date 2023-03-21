import json
from collections import namedtuple
from contextlib import suppress
from os import remove
from pathlib import Path

import pytest

from ..internal import data_parsing as dp
from ..internal import setup_repository as sr
from ..internal.database_interface import QUERIES, DatabaseInterface
from ..internal.helper_functions import CveEntry, CveLookupException, CveSummaryEntry
from .test_database_interface import TEST_QUERIES

PATH_TO_TEST = str(Path(__file__).parent.parent) + '/test/'
YEARTUPLE = namedtuple('years', 'start_year end_year')
YEARS = YEARTUPLE(2016, 2019)

EXISTS_INPUT = [[''], []]
EXISTS_OUTPUT = [True, False]
EXTRACT_CPE_XML = 'test_resources/test_cpe_extract.xml'
UPDATE_CPE_XML = 'test_resources/test_cpe_update.xml'
EXTRACT_CVE_JSON = 'test_resources/test_cve_extract.json'
UPDATE_CVE_JSON = 'test_resources/nvdcve_test_cve_update.json'
EXPECTED_CVE_OUTPUT = json.loads((Path(PATH_TO_TEST) / 'test_resources/expected_cve_output.json').read_text())


EXTRACT_CPE_OUTPUT = [
    'cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
    'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*',
    'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
    'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*',
    'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*',
]

EXPECTED_SUM_OUTPUT = [
    (
        'CVE-2018-20229',
        2018,
        'GitLab Community and Enterprise Edition before 11.3.14, 11.4.x before 11.4.12, and 11.5.x before 11.5.5 allows Directory Traversal.',
        'N/A',
        'N/A',
    ),
    (
        'CVE-2018-8825',
        2018,
        'Google TensorFlow 1.7 and below is affected by: Buffer Overflow. The impact is: execute arbitrary code (local).',
        'N/A',
        'N/A',
    ),
]

EXPECTED_UPDATED_CPE_TABLE = [
    (
        'cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
        'a',
        '\\$0\\.99_kindle_books_project',
        '\\$0\\.99_kindle_books',
        '6',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'android',
        'ANY',
        'ANY',
    ),
    (
        'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*',
        'a',
        '1000guess',
        '1000_guess',
        'N/A',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
    ),
    (
        'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
        'a',
        '1024cms',
        '1024_cms',
        '0\\.7',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
    ),
    (
        'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*',
        'a',
        '1024cms',
        '1024_cms',
        '1\\.2\\.5',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
    ),
    (
        'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*',
        'a',
        '1024cms',
        '1024_cms',
        '1\\.3\\.1',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
    ),
    (
        'cpe:2.3:a:1024cms:1024_cms:1.4.1:*:*:*:*:*:*:*',
        'a',
        '1024cms',
        '1024_cms',
        '1\\.4\\.1',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
    ),
]

EXPECTED_UPDATED_CVE_TABLE = [
    (
        'CVE-2018-0010',
        2018,
        'cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*',
        '4.3',
        'N/A',
        'a',
        'microsoft',
        'ie',
        '6',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
    (
        'CVE-2018-0010',
        2018,
        'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*',
        '4.3',
        'N/A',
        'a',
        'microsoft',
        'ie',
        '7',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
    (
        'CVE-2018-0010',
        2018,
        'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*',
        '4.3',
        'N/A',
        'a',
        'microsoft',
        'ie',
        '8',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
    (
        'CVE-2018-0010',
        2018,
        'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*',
        '4.3',
        'N/A',
        'a',
        'microsoft',
        'ie',
        '9',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
    (
        'CVE-2018-1136',
        2018,
        'cpe:2.3:a:moodle:moodle:*:*:*:*:*:*:*:*',
        '4',
        '4.3',
        'a',
        'moodle',
        'moodle',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '3.1.0',
        '',
        '3.1.11',
        '',
    ),
    (
        'CVE-2018-1136',
        2018,
        'cpe:2.3:a:moodle:moodle:*:*:*:*:*:*:*:*',
        '4',
        '4.3',
        'a',
        'moodle',
        'moodle',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '3.2.0',
        '',
        '3.2.8',
        '',
    ),
    (
        'CVE-2018-1136',
        2018,
        'cpe:2.3:a:moodle:moodle:*:*:*:*:*:*:*:*',
        '4',
        '4.3',
        'a',
        'moodle',
        'moodle',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '3.3.0',
        '',
        '3.3.5',
        '',
    ),
    (
        'CVE-2018-1136',
        2018,
        'cpe:2.3:a:moodle:moodle:*:*:*:*:*:*:*:*',
        '4',
        '4.3',
        'a',
        'moodle',
        'moodle',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '3.4.0',
        '',
        '3.4.2',
        '',
    ),
    (
        'CVE-2018-20229',
        2018,
        'cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*',
        'N/A',
        'N/A',
        'o',
        'microsoft',
        'windows_xp',
        'ANY',
        'sp3',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
    (
        'CVE-2018-20229',
        2018,
        'cpe:2.3:o:microsoft:windows_xp:-:sp2:x64:*:*:*:*:*',
        'N/A',
        'N/A',
        'o',
        'microsoft',
        'windows_xp',
        'N/A',
        'sp2',
        'x64',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
]
EXPECTED_UPDATED_SUMMARY_TABLE = [
    (
        'CVE-2012-0001',
        2012,
        'The kernel in Microsoft Windows XP SP2, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2, R2, '
        'and R2 SP1, and Windows 7 Gold and SP1 does not properly load structured exception handling tables, which allows '
        'context-dependent attackers to bypass the SafeSEH security feature by leveraging a Visual C++ .NET 2003 '
        'application, aka \"Windows Kernel SafeSEH Bypass Vulnerability.\"',
        '9.3',
        'N/A',
    ),
    (
        'CVE-2018-7576',
        2018,
        'Google TensorFlow 1.6.x and earlier is affected by: Null Pointer Dereference. The type of exploitation is: context-dependent.',
        'N/A',
        'N/A',
    ),
    (
        'CVE-2018-8825',
        2018,
        'Google TensorFlow 1.7 and below is affected by: Buffer Overflow. The impact is: execute arbitrary code (local).',
        'N/A',
        'N/A',
    ),
]

EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT = [
    CveEntry(
        cve_id='CVE-2012-0001',
        impact={'cvssV2': 9.3},
        cpe_list=[
            ('cpe:2.3:o:microsoft:windows_xp:*:sp2:professional_x64:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_server_2008:r2:*:itanium:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_server_2008:r2:*:x64:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_server_2008:-:sp2:itanium:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_7:-:sp1:x64:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:itanium:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_vista:*:sp2:x64:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_7:-:sp1:x86:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:x64:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x64:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x32:*:*:*:*:*', '', '', '', ''),
        ],
    ),
    CveEntry(
        cve_id='CVE-2018-0010',
        impact={'cvssV2': 4.3},
        cpe_list=[
            ('cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*', '', '', '', ''),
        ],
    ),
]

EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT = [
    CveSummaryEntry(
        'CVE-2018-20229',
        'GitLab Community and Enterprise Edition before 11.3.14, 11.4.x before 11.4.12, and 11.5.x before 11.5.5 '
        'allows Directory Traversal.',
        {},
    ),
    CveSummaryEntry(
        'CVE-2018-8825',
        'Google TensorFlow 1.7 and below is affected by: Buffer Overflow. The impact is: execute arbitrary code (local).',
        {},
    ),
]

# contain input and expected results of the setup_cve_format function
CVE_LIST = [
    CveEntry(
        'CVE-2012-0001',
        {},
        [
            ('cpe:2.3:a:\\$0.99_kindle_bo\\:oks_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*', '', '', '', ''),
            ('cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*', '', '', '', ''),
            ('cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*', '', '', '', ''),
        ],
    ),
    CveEntry('CVE-2012-0002', {'cvssV2': '5.3'}, [('cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*', '', '', '', '')]),
]
CVE_TABLE = [
    (
        'CVE-2012-0001',
        '2012',
        'cpe:2.3:a:\\$0.99_kindle_bo\\:oks_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
        'N/A',
        'N/A',
        'a',
        '\\$0\\.99_kindle_bo\\:oks_project',
        '\\$0\\.99_kindle_books',
        '6',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'android',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
    (
        'CVE-2012-0001',
        '2012',
        'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*',
        'N/A',
        'N/A',
        'a',
        '1000guess',
        '1000_guess',
        'N/A',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
    (
        'CVE-2012-0001',
        '2012',
        'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
        'N/A',
        'N/A',
        'a',
        '1024cms',
        '1024_cms',
        '0\\.7',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
    (
        'CVE-2012-0001',
        '2012',
        'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*',
        'N/A',
        'N/A',
        'a',
        '1024cms',
        '1024_cms',
        '1\\.2\\.5',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
    (
        'CVE-2012-0002',
        '2012',
        'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*',
        '5.3',
        'N/A',
        'a',
        '1024cms',
        '1024_cms',
        '1\\.3\\.1',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        '',
        '',
        '',
        '',
    ),
]

# contain input and expected results of the setup_cpe_format function
CPE_LIST = [
    'cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
    'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*',
    'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
    'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*',
    'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*',
]
CPE_TABLE = [
    (
        'cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
        'a',
        '\\$0\\.99_kindle_books_project',
        '\\$0\\.99_kindle_books',
        '6',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'android',
        'ANY',
        'ANY',
    ),
    (
        'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*',
        'a',
        '1000guess',
        '1000_guess',
        'N/A',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
    ),
    (
        'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
        'a',
        '1024cms',
        '1024_cms',
        '0\\.7',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
    ),
    (
        'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*',
        'a',
        '1024cms',
        '1024_cms',
        '1\\.2\\.5',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
    ),
    (
        'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*',
        'a',
        '1024cms',
        '1024_cms',
        '1\\.3\\.1',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
        'ANY',
    ),
]


@pytest.fixture(autouse=True)
def setup():
    with suppress(OSError):
        remove('cve_cpe.db')
    sr.QUERIES.update(TEST_QUERIES)
    cpe_base = sr.setup_cpe_table(dp.extract_cpe(PATH_TO_TEST + EXTRACT_CPE_XML))
    cve_base, summary_base = dp.extract_cve(PATH_TO_TEST + EXTRACT_CVE_JSON)
    cve_base = sr.setup_cve_feeds_table(cve_list=cve_base)
    summary_base = sr.setup_cve_summary_table(summary_list=summary_base)

    with DatabaseInterface(PATH_TO_TEST + 'test_update.db') as db:
        db.execute_query(query=QUERIES['create_cpe_table'].format('cpe_table'))
        db.insert_rows(query=QUERIES['insert_cpe'].format('cpe_table'), input_data=cpe_base)
        db.execute_query(query=QUERIES['create_cve_table'].format('cve_table'))
        db.execute_query(query=QUERIES['create_summary_table'].format('summary_table'))
        db.insert_rows(query=QUERIES['insert_cve'].format('cve_table'), input_data=cve_base)
        db.insert_rows(query=QUERIES['insert_summary'].format('summary_table'), input_data=summary_base)

        db.execute_query(query=TEST_QUERIES['test_create_update'].format('outdated'))
        db.execute_query(query=TEST_QUERIES['test_create_update'].format('new'))
        db.insert_rows(
            query=TEST_QUERIES['test_insert_cve_id'].format('outdated'),
            input_data=[('CVE-2018-0001', 2018), ('CVE-2018-0002', 2018)],
        )
        db.insert_rows(
            query=TEST_QUERIES['test_insert_cve_id'].format('new'),
            input_data=[('CVE-2018-0002', 2018), ('CVE-2018-0003', 2018)],
        )

    yield

    with suppress(OSError):
        remove(PATH_TO_TEST + 'test_update.db')
        remove(PATH_TO_TEST + 'test_import.db')
        remove(PATH_TO_TEST + 'test_output.db')


@pytest.fixture(scope='function', autouse=True)
def patch_download(monkeypatch):
    class MockRequests:
        content = b''

    monkeypatch.setattr(dp.ZipFile, '_RealGetContents', lambda *_, **__: None)
    monkeypatch.setattr(dp.requests, 'get', lambda *_, **__: MockRequests)


def test_overlap():
    assert sr.overlap(requested_years=YEARS, years_in_cve_database=[2015, 2016, 2017]) == [2018, 2019]


def test_exists(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr.DATABASE, 'fetch_multiple', lambda *_, **__: EXISTS_INPUT[0])
        assert EXISTS_OUTPUT[0] == sr.table_exists(table_name='')
        monkey.setattr(sr.DATABASE, 'fetch_multiple', lambda *_, **__: EXISTS_INPUT[1])
        assert EXISTS_OUTPUT[1] == sr.table_exists(table_name='')


def test_extract_relevant_feeds():
    sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_update.db')
    assert sorted(sr.extract_relevant_feeds(from_table='new', where_table='outdated')) == [
        ('CVE-2018-0002', 2018),
        ('CVE-2018-0003', 2018),
    ]


def test_delete_outdated_feeds():
    sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_update.db')
    sr.delete_outdated_feeds(delete_outdated_from='outdated', use_for_selection='new')
    assert sr.DATABASE.fetch_one(query=QUERIES['select_all'].format('outdated'))[0] == 'CVE-2018-0001'


def test_create_insert_delete():
    sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_import.db')
    sr.create(query='test_create', table_name='test')
    assert sr.DATABASE.fetch_one(query=QUERIES['exist'].format('test'))[0] == 'test'

    sr.insert_into(query='test_insert', table_name='test', input_data=[(1,), (2,)])
    assert sorted(sr.DATABASE.fetch_multiple(query=QUERIES['select_all'].format('test'))) == [(1,), (2,)]

    sr.drop_table('test')
    assert list(sr.DATABASE.fetch_multiple(query=QUERIES['exist'].format('test'))) == []


def test_update_cpe(monkeypatch):
    with monkeypatch.context() as monkey:
        sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_update.db')
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + UPDATE_CPE_XML])
        sr.update_cpe('')
        actual_cpe_update = sorted(sr.DATABASE.fetch_multiple(query=QUERIES['select_all'].format('cpe_table')))
        assert sorted(EXPECTED_UPDATED_CPE_TABLE) == actual_cpe_update
        sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_output.db')
        with pytest.raises(CveLookupException) as exception:
            sr.update_cpe('')
            assert 'CPE table does not exist' in exception.message


def test_import_cpe(monkeypatch):
    with monkeypatch.context() as monkey:
        sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_import.db')
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + EXTRACT_CPE_XML])
        sr.import_cpe('')
        actual_cpe_output = sr.DATABASE.fetch_multiple(QUERIES['select_all'].format('cpe_table'))
        assert sorted(CPE_TABLE) == sorted(actual_cpe_output)
        sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_output.db')
        sr.DATABASE.execute_query(QUERIES['create_cpe_table'].format('cpe_table'))
        with pytest.raises(CveLookupException) as exception:
            sr.import_cpe('')
            assert 'CPE table does already exist' in exception.message


def test_get_cpe_content(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + EXTRACT_CPE_XML])
        EXTRACT_CPE_OUTPUT.sort()
        actual_output = sr.get_cpe_content(path=PATH_TO_TEST + EXTRACT_CPE_XML)
        actual_output.sort()
        assert EXTRACT_CPE_OUTPUT == actual_output

    with pytest.raises(Exception):
        sr.get_cpe_content('.')


def test_init_cve_feeds_table():
    sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_import.db')
    expected = [
        (
            'CVE-2012-0001',
            2012,
            'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*',
            'N/A',
            'N/A',
            'a',
            '1000guess',
            '1000_guess',
            'N/A',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            '',
            '',
            '',
            '',
        ),
        (
            'CVE-2012-0001',
            2012,
            'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*',
            'N/A',
            'N/A',
            'a',
            '1024cms',
            '1024_cms',
            '0\\.7',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            '',
            '',
            '',
            '',
        ),
        (
            'CVE-2012-0001',
            2012,
            'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*',
            'N/A',
            'N/A',
            'a',
            '1024cms',
            '1024_cms',
            '1\\.2\\.5',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            '',
            '',
            '',
            '',
        ),
        (
            'CVE-2012-0001',
            2012,
            'cpe:2.3:a:\\$0.99_kindle_bo\\:oks_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
            'N/A',
            'N/A',
            'a',
            '\\$0\\.99_kindle_bo\\:oks_project',
            '\\$0\\.99_kindle_books',
            '6',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'android',
            'ANY',
            'ANY',
            '',
            '',
            '',
            '',
        ),
        (
            'CVE-2012-0002',
            2012,
            'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*',
            '5.3',
            'N/A',
            'a',
            '1024cms',
            '1024_cms',
            '1\\.3\\.1',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            '',
            '',
            '',
            '',
        ),
    ]
    sr.init_cve_feeds_table(CVE_LIST, 'test_cve')
    assert sr.DATABASE.fetch_one(QUERIES['exist'].format('test_cve'))[0] == 'test_cve'
    db_cve = sorted(sr.DATABASE.fetch_multiple(QUERIES['select_all'].format('test_cve')))
    assert len(db_cve) == 5
    assert db_cve == expected


def test_init_summaries_table():
    sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_import.db')
    sr.init_cve_summaries_table(EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT, 'test_summary')
    assert sr.DATABASE.fetch_one(QUERIES['exist'].format('test_summary'))[0] == 'test_summary'
    db_summary = list(sr.DATABASE.fetch_multiple(QUERIES['select_all'].format('test_summary')))
    db_summary.sort()
    EXPECTED_SUM_OUTPUT.sort()
    assert db_summary == EXPECTED_SUM_OUTPUT


def test_get_cve_import_content(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + EXTRACT_CVE_JSON])
        feeds, summary = sr.get_cve_import_content('', [2003])
        assert len(feeds) == len(EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT)
        for item, expected in zip(feeds, EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT):
            assert item.cve_id == expected.cve_id
            assert item.impact == expected.impact
            assert sorted(item.cpe_list) == sorted(expected.cpe_list)
        assert summary == EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT


def test_get_cve_update_content(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + EXTRACT_CVE_JSON])
        feeds, summary = sr.get_cve_update_content('')
        for item, expected in zip(feeds, EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT):
            assert item.cve_id == expected.cve_id
            assert item.impact == expected.impact
            assert sorted(item.cpe_list) == sorted(expected.cpe_list)
        assert EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT == summary

    with pytest.raises(Exception):
        sr.get_cve_update_content('.')


def test_update_cve_repository(monkeypatch):
    with monkeypatch.context() as monkey:
        sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_update.db')
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + UPDATE_CVE_JSON])
        sr.update_cve_repository(cve_extract_path='')
        actual_cve_update = list(sr.DATABASE.fetch_multiple(QUERIES['select_all'].format('cve_table')))
        actual_summary_update = list(sr.DATABASE.fetch_multiple(QUERIES['select_all'].format('summary_table')))
        assert sorted(actual_cve_update) == sorted(EXPECTED_UPDATED_CVE_TABLE)
        assert sorted(actual_summary_update) == sorted(EXPECTED_UPDATED_SUMMARY_TABLE)
        sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_output.db')

        with pytest.raises(CveLookupException) as exception:
            sr.update_cve_repository('.')
            assert 'CVE tables do not exist!' in exception.message
        sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_update.db')


def test_update_cve_feeds():
    db_cve = list(sr.DATABASE.fetch_multiple(QUERIES['select_all'].format('cve_table')))
    assert sorted(db_cve) == sorted(EXPECTED_UPDATED_CVE_TABLE)


def test_update_cve_summaries():
    db_summary = list(sr.DATABASE.fetch_multiple(QUERIES['select_all'].format('summary_table')))
    assert sorted(db_summary) == sorted(EXPECTED_UPDATED_SUMMARY_TABLE)


def test_get_years_from_database():
    sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_update.db')
    assert sorted(sr.get_years_from_database()) == [2012, 2018]


def test_import_cve(monkeypatch):
    with monkeypatch.context() as monkey:
        sr.DATABASE = sr.DatabaseInterface(PATH_TO_TEST + 'test_import.db')
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + EXTRACT_CVE_JSON])
        sr.import_cve(cve_extract_path='', years=YEARS)
        actual_cve_output = list(sr.DATABASE.fetch_multiple(QUERIES['select_all'].format('cve_table')))
        actual_summary_output = list(sr.DATABASE.fetch_multiple(QUERIES['select_all'].format('summary_table')))
        assert sorted(actual_cve_output) == [tuple(item) for item in EXPECTED_CVE_OUTPUT]
        assert sorted(actual_summary_output) == sorted(EXPECTED_SUM_OUTPUT)


@pytest.mark.parametrize(
    'path, choice, years, expected',
    [
        ('', sr.Choice('both'), YEARS, ['cpe', 'cve']),
        ('', sr.Choice('cpe'), YEARS, ['cpe']),
        ('', sr.Choice('cve'), YEARS, ['cve']),
    ],
)
def test_set_repository(monkeypatch, path, choice, years, expected):
    output = []
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'import_cpe', lambda *_, **__: output.append('cpe'))
        monkey.setattr(sr, 'import_cve', lambda *_, **__: output.append('cve'))
        sr.init_repository(path, choice, years)
        assert output == expected


@pytest.mark.parametrize(
    'path, choice, expected',
    [
        ('', sr.Choice('both'), ['cpe', 'cve']),
        ('', sr.Choice('cpe'), ['cpe']),
        ('', sr.Choice('cve'), ['cve']),
    ],
)
def test_update_repository(monkeypatch, path, choice, expected):
    output = []
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'update_cpe', lambda *_, **__: output.append('cpe'))
        monkey.setattr(sr, 'update_cve_repository', lambda *_, **__: output.append('cve'))
        sr.update_repository(path, choice)
        assert output == expected


@pytest.mark.parametrize(
    'years, raising',
    [(YEARTUPLE(2002, 2019), None), (YEARTUPLE(2001, 2019), ValueError), (YEARTUPLE(2018, 2017), ValueError)],
)
def test_check_validity_of_arguments(years, raising):
    if raising:
        with pytest.raises(ValueError):
            sr.check_validity_of_arguments(years=years)
    else:
        sr.check_validity_of_arguments(years=years)


def test_setup_cve_feeds_table():
    cve_result = sr.setup_cve_feeds_table(CVE_LIST)
    assert CVE_TABLE == cve_result


def test_setup_cve_summary_table():
    summary_input = [
        CveSummaryEntry('CVE-2018-20229', 'some description ...', {'cvssV2': '5.3'}),
        CveSummaryEntry('CVE-2018-0010', 'foobar', {'cvssV2': '7.3', 'cvssV3': '8.3'}),
    ]
    expected_output = [
        ('CVE-2018-20229', '2018', 'some description ...', '5.3', 'N/A'),
        ('CVE-2018-0010', '2018', 'foobar', '7.3', '8.3'),
    ]
    summary_result = sr.setup_cve_summary_table(summary_input)
    assert summary_result == expected_output


def test_setup_cpe_table():
    result = sr.setup_cpe_table(CPE_LIST)
    for entry in result:
        assert len(entry) == 12
    for actual, expected in zip(result, CPE_TABLE):
        assert actual == expected


def test_setup_cpe_entry_with_colons():
    result = sr.setup_cpe_table(
        [
            'cpe:2.3:a:net::netmask_project:net::netmask:*:*:*:*:*:perl:*:*',
            'cpe:2.3:a:lemonldap-ng:lemonldap\\:\\::1.0.3:*:*:*:*:*:*:*',
        ]
    )
    expected_result = [
        (
            'cpe:2.3:a:net::netmask_project:net::netmask:*:*:*:*:*:perl:*:*',
            'a',
            'net::netmask_project',
            'net::netmask',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'perl',
            'ANY',
            'ANY',
        ),
        (
            'cpe:2.3:a:lemonldap-ng:lemonldap\\:\\::1.0.3:*:*:*:*:*:*:*',
            'a',
            'lemonldap\\-ng',
            'lemonldap\\:\\:',
            '1\\.0\\.3',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
            'ANY',
        ),
    ]
    for entry in result:
        assert len(entry) == 12
    for actual, expected in zip(result, expected_result):
        assert actual == expected

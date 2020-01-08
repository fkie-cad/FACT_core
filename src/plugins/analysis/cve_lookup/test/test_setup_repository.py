import sys
from collections import namedtuple
from os import remove
from pathlib import Path

import pytest

try:
    from internal import data_prep as dp
    from internal import setup_repository as sr
    from internal.database_interface import DB, QUERIES
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    import data_prep as dp
    from database_interface import DB, get_meta
    import setup_repository as sr

PATH_TO_TEST = str(Path(__file__).parent.parent) + '/test/'
YEARTUPLE = namedtuple('years', 'start_year end_year')
YEARS = YEARTUPLE(2016, 2019)

DATABASE_YEARS_INPUT = [2015, 2016, 2017]
OVERLAP_OUTPUT = [2018, 2019]

EXISTS_INPUT = [[''], []]
EXISTS_OUTPUT = [True, False]
EXTRACT_CPE_XML = 'test_resources/test_cpe_extract.xml'
UPDATE_CPE_XML = 'test_resources/test_cpe_update.xml'
EXTRACT_CVE_JSON = 'test_resources/test_cve_extract.json'
UPDATE_CVE_JSON = 'test_resources/nvdcve_test_cve_update.json'

EXPECTED_CPE_OUTPUT = [('cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*', 'a',
                        '\\$0\\.99_kindle_books_project', '\\$0\\.99_kindle_books', '6', 'ANY', 'ANY', 'ANY', 'ANY', 'android', 'ANY', 'ANY'),
                       ('cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*', 'a', '1000guess', '1000_guess', 'NA',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '0\\.7', 'ANY',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '1\\.2\\.5',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '1\\.3\\.1',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY')]

EXPECTED_CVE_OUTPUT = [('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*', 'o', 'microsoft',
                        'windows_7', 'NA', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_7:-:sp1:x64:*:*:*:*:*', 'o', 'microsoft',
                        'windows_7', 'NA', 'sp1', 'x64', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_7:-:sp1:x86:*:*:*:*:*', 'o', 'microsoft',
                        'windows_7', 'NA', 'sp1', 'x86', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*', 'o',
                        'microsoft', 'windows_server_2003', 'ANY', 'sp2', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x32:*:*:*:*:*', 'o',
                        'microsoft', 'windows_server_2008', 'ANY', 'sp2', 'x32', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x64:*:*:*:*:*', 'o',
                        'microsoft', 'windows_server_2008', 'ANY', 'sp2', 'x64', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_server_2008:-:sp2:itanium:*:*:*:*:*', 'o',
                        'microsoft', 'windows_server_2008', 'NA', 'sp2', 'itanium', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_server_2008:r2:*:itanium:*:*:*:*:*', 'o',
                        'microsoft', 'windows_server_2008', 'r2', 'ANY', 'itanium', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_server_2008:r2:*:x64:*:*:*:*:*', 'o',
                        'microsoft', 'windows_server_2008', 'r2', 'ANY', 'x64', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:itanium:*:*:*:*:*', 'o',
                        'microsoft', 'windows_server_2008', 'r2', 'sp1', 'itanium', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:x64:*:*:*:*:*', 'o',
                        'microsoft', 'windows_server_2008', 'r2', 'sp1', 'x64', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*', 'o',
                        'microsoft', 'windows_vista', 'ANY', 'sp2', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_vista:*:sp2:x64:*:*:*:*:*', 'o',
                        'microsoft', 'windows_vista', 'ANY', 'sp2', 'x64', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2012-0001', 2012, 'cpe:2.3:o:microsoft:windows_xp:*:sp2:professional_x64:*:*:*:*:*', 'o',
                        'microsoft', 'windows_xp', 'ANY', 'sp2', 'professional_x64', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2018-0010', 2018, 'cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie', '6',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2018-0010', 2018, 'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie', '7',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2018-0010', 2018, 'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie', '8',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2018-0010', 2018, 'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie', '9',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY')]

EXTRACT_CPE_OUTPUT = ['cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
                      'cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*',
                      'cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*', 'cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*',
                      'cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*']

EXPECTED_SUM_OUTPUT = [('CVE-2018-20229', 2018, 'GitLab Community and Enterprise Edition before 11.3.14, 11.4.x before '
                                                '11.4.12, and 11.5.x before 11.5.5 allows Directory Traversal.'),
                       ('CVE-2018-8825', 2018, 'Google TensorFlow 1.7 and below is affected by: Buffer Overflow. '
                                               'The impact is: execute arbitrary code (local).')]

EXPECTED_UPDATED_CPE_TABLE = [('cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*',
                               'a', '\\$0\\.99_kindle_books_project', '\\$0\\.99_kindle_books', '6', 'ANY', 'ANY',
                               'ANY', 'ANY', 'android', 'ANY', 'ANY'),
                              ('cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*', 'a', '1000guess', '1000_guess', 'NA',
                               'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '0\\.7',
                               'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms',
                               '1\\.2\\.5', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms',
                               '1\\.3\\.1', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('cpe:2.3:a:1024cms:1024_cms:1.4.1:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms',
                               '1\\.4\\.1', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY')]

EXPECTED_UPDATED_CVE_TABLE = [('CVE-2018-0010', 2018, 'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie',
                               '7', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('CVE-2018-0010', 2018, 'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie',
                               '9', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('CVE-2018-0010', 2018, 'cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie',
                               '6', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('CVE-2018-0010', 2018, 'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie',
                               '8', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('CVE-2018-20229', 2018, 'cpe:2.3:o:microsoft:windows_xp:*:sp3:*:*:*:*:*:*', 'o',
                               'microsoft', 'windows_xp', 'ANY', 'sp3', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('CVE-2018-20229', 2018, 'cpe:2.3:o:microsoft:windows_xp:-:sp2:x64:*:*:*:*:*', 'o',
                               'microsoft', 'windows_xp', 'NA', 'sp2', 'x64', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                              ('CVE-2018-1136', 2018, 'cpe:2.3:a:moodle:moodle:*:*:*:*:*:*:*:*', 'a', 'moodle',
                               'moodle', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY')]
EXPECTED_UPDATED_SUMMARY_TABLE = [('CVE-2012-0001', 2012, 'The kernel in Microsoft Windows XP SP2, Windows Server '
                                   '2003 SP2, Windows Vista SP2, Windows Server 2008 SP2, R2, and R2 SP1, and Windows 7'
                                   ' Gold and SP1 does not properly load structured exception handling tables, which '
                                   'allows context-dependent attackers to bypass the SafeSEH security feature by '
                                   'leveraging a Visual C++ .NET 2003 application, aka \"Windows Kernel SafeSEH Bypass '
                                   'Vulnerability.\"'),
                                  ('CVE-2018-7576', 2018, 'Google TensorFlow 1.6.x and earlier is affected by: Null '
                                   'Pointer Dereference. The type of exploitation is: context-dependent.'),
                                  ('CVE-2018-8825', 2018, 'Google TensorFlow 1.7 and below is affected by: Buffer '
                                   'Overflow. The impact is: execute arbitrary code (local).')]

EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT = ['CVE-2012-0001', 'cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x32:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_server_2008:r2:*:x64:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_server_2008:-:sp2:itanium:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_7:-:sp1:x86:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_7:-:sp1:x64:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:itanium:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:x64:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_server_2008:r2:*:itanium:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_xp:*:sp2:professional_x64:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x64:*:*:*:*:*',
                                         'cpe:2.3:o:microsoft:windows_vista:*:sp2:x64:*:*:*:*:*', 'CVE-2018-0010',
                                         'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*', 'cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*',
                                         'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*', 'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*']


EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT = ['CVE-2018-20229', 'GitLab Community and Enterprise Edition before 11.3.14, 11.4.x before '
                                           '11.4.12, and 11.5.x before 11.5.5 allows Directory Traversal.', 'CVE-2018-8825',
                                           'Google TensorFlow 1.7 and below is affected by: Buffer Overflow. '
                                           'The impact is: execute arbitrary code (local).']


@pytest.fixture(scope='session', autouse=True)
def setup() -> None:
    try:
        remove('cve_cpe.db')
    except OSError:
        pass
    cpe_base = dp.setup_cpe_table(dp.extract_cpe(PATH_TO_TEST + EXTRACT_CPE_XML))
    cve_base, summary_base = dp.extract_cve(PATH_TO_TEST + EXTRACT_CVE_JSON)
    cve_base, summary_base = dp.setup_cve_feeds_table(cve_list=cve_base), dp.setup_cve_summary_table(summary_list=summary_base)

    with DB(PATH_TO_TEST + 'test_update.db') as db:
        db.table_manager(query=QUERIES['create_cpe_table'].format('cpe_table'))
        db.insert_rows(query=QUERIES['insert_cpe'].format('cpe_table'), input_t=cpe_base)
        db.table_manager(query=QUERIES['create_cve_table'].format('cve_table'))
        db.table_manager(query=QUERIES['create_summary_table'].format('summary_table'))
        db.insert_rows(query=QUERIES['insert_cve'].format('cve_table'), input_t=cve_base)
        db.insert_rows(query=QUERIES['insert_summary'].format('summary_table'), input_t=summary_base)

        db.table_manager(query=QUERIES['test_create_update'].format('outdated'))
        db.table_manager(query=QUERIES['test_create_update'].format('new'))
        db.insert_rows(query=QUERIES['test_insert_cve_id'].format('outdated'), input_t=[('CVE-2018-0001', 2018), ('CVE-2018-0002', 2018)])
        db.insert_rows(query=QUERIES['test_insert_cve_id'].format('new'), input_t=[('CVE-2018-0002', 2018), ('CVE-2018-0003', 2018)])

    yield None
    try:
        remove(PATH_TO_TEST + 'test_update.db')
        remove(PATH_TO_TEST + 'test_import.db')
        remove(PATH_TO_TEST + 'test_output.db')
    except OSError:
        pass


@pytest.fixture(scope='function', autouse=True)
def patch_download(monkeypatch):

    class MockRequests:
        content = b''

    monkeypatch.setattr(dp.ZipFile, '_RealGetContents', lambda *_, **__: None)
    monkeypatch.setattr(dp.requests, 'get', lambda *_, **__: MockRequests)


def test_overlap():
    assert OVERLAP_OUTPUT == sr.overlap(requested_years=YEARS, years_in_cve_database=DATABASE_YEARS_INPUT)


def test_exists(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr.DATABASE, 'select_query', lambda *_, **__: EXISTS_INPUT[0])
        assert EXISTS_OUTPUT[0] == sr.exists(table_name='')
        monkey.setattr(sr.DATABASE, 'select_query', lambda *_, **__: EXISTS_INPUT[1])
        assert EXISTS_OUTPUT[1] == sr.exists(table_name='')


def test_extract_relevant_feeds():
    sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_update.db')
    assert [('CVE-2018-0002', 2018), ('CVE-2018-0003', 2018)] == sr.extract_relevant_feeds(from_table='new', where_table='outdated')


def test_delete_outdated_feeds():
    sr.delete_outdated_feeds(delete_outdated_from='outdated', use_for_selection='new')
    assert sr.DATABASE.select_single(query=QUERIES['select_all'].format('outdated'))[0] == 'CVE-2018-0001'


def test_create():
    sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_import.db')
    sr.create(query='test_create', table_name='test')
    assert sr.DATABASE.select_single(query=QUERIES['exist'].format('test'))[0] == 'test'


def test_insert_into():
    sr.insert_into(query='test_insert', table_name='test', input_data=[(1, ), (2, )])
    assert [(1, ), (2, )] == list(sr.DATABASE.select_query(query=QUERIES['select_all'].format('test')))


def test_drop_table():
    sr.drop_table('test')
    assert [] == list(sr.DATABASE.select_query(query=QUERIES['exist'].format('test')))


def test_update_cpe(monkeypatch, capsys):
    with monkeypatch.context() as monkey:
        sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_update.db')
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + UPDATE_CPE_XML])
        sr.update_cpe('')
        EXPECTED_UPDATED_CPE_TABLE.sort()
        actual_cpe_update = list(sr.DATABASE.select_query(query=QUERIES['select_all'].format('cpe_table')))
        actual_cpe_update.sort()
        assert EXPECTED_UPDATED_CPE_TABLE == actual_cpe_update
        sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_output.db')
        sr.update_cpe('')
        assert capsys.readouterr().out == '\nCPE table does not exist! Did you mean import CPE?\n\n'


def test_import_cpe(monkeypatch, capsys):
    with monkeypatch.context() as monkey:
        sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_import.db')
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + EXTRACT_CPE_XML])
        sr.import_cpe('')
        EXPECTED_CPE_OUTPUT.sort()
        actual_cpe_output = list(sr.DATABASE.select_query(QUERIES['select_all'].format('cpe_table')))
        actual_cpe_output.sort()
        assert EXPECTED_CPE_OUTPUT == actual_cpe_output
        sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_output.db')
        sr.DATABASE.table_manager(QUERIES['create_cpe_table'].format('cpe_table'))
        sr.import_cpe('')
        assert capsys.readouterr().out == '\nCPE table does already exist!\n\n'


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
    sr.init_cve_feeds_table(EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT, 'test_cve')
    assert sr.DATABASE.select_single(QUERIES['exist'].format('test_cve'))[0] == 'test_cve'
    db_cve = list(sr.DATABASE.select_query(QUERIES['select_all'].format('test_cve')))
    db_cve.sort()
    EXPECTED_CVE_OUTPUT.sort()
    assert db_cve == EXPECTED_CVE_OUTPUT


def test_init_summaries_table():
    sr.init_cve_summaries_table(EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT, 'test_summary')
    assert sr.DATABASE.select_single(QUERIES['exist'].format('test_summary'))[0] == 'test_summary'
    db_summary = list(sr.DATABASE.select_query(QUERIES['select_all'].format('test_summary')))
    db_summary.sort()
    EXPECTED_SUM_OUTPUT.sort()
    assert db_summary == EXPECTED_SUM_OUTPUT


def test_get_cve_import_content(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + EXTRACT_CVE_JSON])
        feeds, summary = sr.get_cve_update_content('')
        EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT.sort()
        feeds.sort()
        EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT.sort()
        summary.sort()
        assert EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT == feeds
        assert EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT == summary


def test_get_cve_update_content(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + EXTRACT_CVE_JSON])
        feeds, summary = sr.get_cve_update_content('')
        EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT.sort()
        feeds.sort()
        EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT.sort()
        summary.sort()
        assert EXPECTED_GET_CVE_FEEDS_UPDATE_CONTENT == feeds
        assert EXPECTED_GET_CVE_SUMMARY_UPDATE_CONTENT == summary

    with pytest.raises(Exception):
        sr.get_cve_update_content('.')


def test_cve_summaries_can_be_imported():
    assert sr.cve_summaries_can_be_imported(['']) is True
    assert sr.cve_summaries_can_be_imported([]) is False


def test_update_cve_repository(monkeypatch, capsys):
    with monkeypatch.context() as monkey:
        sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_update.db')
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + UPDATE_CVE_JSON])
        sr.update_cve_repository(cve_extract_path='')
        EXPECTED_UPDATED_CVE_TABLE.sort()
        actual_cve_update = list(sr.DATABASE.select_query(QUERIES['select_all'].format('cve_table')))
        actual_cve_update.sort()
        EXPECTED_UPDATED_SUMMARY_TABLE.sort()
        actual_summary_update = list(sr.DATABASE.select_query(QUERIES['select_all'].format('summary_table')))
        actual_summary_update.sort()
        assert EXPECTED_UPDATED_CVE_TABLE == actual_cve_update
        assert EXPECTED_UPDATED_SUMMARY_TABLE == actual_summary_update
        sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_output.db')
        sr.update_cve_repository('.')
        assert capsys.readouterr().out == '\nCVE tables do not exist! Did you mean import CVE?\n\n'
        sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_update.db')


def test_update_cve_feeds():
    db_cve = list(sr.DATABASE.select_query(QUERIES['select_all'].format('cve_table')))
    db_cve.sort()
    EXPECTED_UPDATED_CVE_TABLE.sort()
    assert db_cve == EXPECTED_UPDATED_CVE_TABLE


def test_update_cve_summaries(monkeypatch, capsys):
    db_summary = list(sr.DATABASE.select_query(QUERIES['select_all'].format('summary_table')))
    db_summary.sort()
    EXPECTED_UPDATED_SUMMARY_TABLE.sort()
    assert db_summary == EXPECTED_UPDATED_SUMMARY_TABLE


def test_get_years_from_database():
    sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_update.db')
    assert sr.get_years_from_database()[0] == 2018


def test_import_cve(monkeypatch):
    with monkeypatch.context() as monkey:
        sr.DATABASE = sr.DB(PATH_TO_TEST + 'test_import.db')
        monkey.setattr(sr, 'glob', lambda *_, **__: [PATH_TO_TEST + EXTRACT_CVE_JSON])
        sr.import_cve(cve_extract_path='', years=YEARS)
        EXPECTED_CVE_OUTPUT.sort()
        EXPECTED_SUM_OUTPUT.sort()
        actual_cve_output = list(sr.DATABASE.select_query(QUERIES['select_all'].format('cve_table')))
        actual_summary_output = list(sr.DATABASE.select_query(QUERIES['select_all'].format('summary_table')))
        actual_cve_output.sort()
        actual_summary_output.sort()
        assert EXPECTED_CVE_OUTPUT == actual_cve_output
        assert EXPECTED_SUM_OUTPUT == actual_summary_output


@pytest.mark.parametrize('path, specify, years, expected', [('', 0, YEARS, ['cpe', 'cve']), ('', 1, YEARS, ['cpe']), ('', 2, YEARS, ['cve'])])
def test_set_repository(monkeypatch, path, specify, years, expected):
    output = list()
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'import_cpe', lambda *_, **__: output.append('cpe'))
        monkey.setattr(sr, 'import_cve', lambda *_, **__: output.append('cve'))
        sr.set_repository(extraction_path=path, specify=specify, years=years)
        assert output == expected


@pytest.mark.parametrize('path, specify, expected', [('', 0, ['cpe', 'cve']), ('', 1, ['cpe']), ('', 2, ['cve'])])
def test_update_repository(monkeypatch, path, specify, expected):
    output = list()
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'update_cpe', lambda *_, **__: output.append('cpe'))
        monkey.setattr(sr, 'update_cve_repository', lambda *_, **__: output.append('cve'))
        sr.update_repository(extraction_path=path, specify=specify)
        assert output == expected


@pytest.mark.parametrize('specify, years, raising', [(-1, YEARTUPLE(2002, 2019), ValueError), (0, YEARTUPLE(2002, 2019), None),
                                                     (3, YEARS, ValueError), (0, YEARTUPLE(2001, 2019), ValueError),
                                                     (0, YEARTUPLE(2018, 2017), ValueError)])
def test_check_validity_of_arguments(specify, years, raising):
    if raising:
        with pytest.raises(ValueError):
            sr.check_validity_of_arguments(specify=specify, years=years)
    else:
        sr.check_validity_of_arguments(specify=specify, years=years)

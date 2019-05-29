from os import remove
from pathlib import Path
from sys import path

import pytest

from ..internal import data_prep as dp
from ..internal import meta
from ..internal import setup_repository as sr

METADATA = meta.get_meta()


EXPECTED_CPE_OUTPUT = [('cpe:2.3:a:\\$0.99_kindle_books_project:\\$0.99_kindle_books:6:*:*:*:*:android:*:*', 'a',
                        '\\$0\\.99_kindle_books_project', '\\$0\\.99_kindle_books', '6', 'ANY', 'ANY', 'ANY', 'ANY',
                        'android', 'ANY', 'ANY'),
                       ('cpe:2.3:a:1000guess:1000_guess:-:*:*:*:*:*:*:*', 'a', '1000guess', '1000_guess', 'NA', 'ANY',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('cpe:2.3:a:1024cms:1024_cms:0.7:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '0\\.7', 'ANY',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('cpe:2.3:a:1024cms:1024_cms:1.2.5:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '1\\.2\\.5',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('cpe:2.3:a:1024cms:1024_cms:1.3.1:*:*:*:*:*:*:*', 'a', '1024cms', '1024_cms', '1\\.3\\.1',
                        'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY')]

EXPECTED_CVE_OUTPUT = [('CVE-2018-0010', '2018', 'cpe:2.3:a:microsoft:ie:7:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie',
                        '7', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2018-0010', '2018', 'cpe:2.3:a:microsoft:ie:9:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie',
                        '9', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2018-0010', '2018', 'cpe:2.3:a:microsoft:ie:6:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie',
                        '6', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY'),
                       ('CVE-2018-0010', '2018', 'cpe:2.3:a:microsoft:ie:8:*:*:*:*:*:*:*', 'a', 'microsoft', 'ie',
                        '8', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY', 'ANY')]
EXPECTED_SUM_OUTPUT = [('CVE-2018-20229', '2018', 'GitLab Community and Enterprise Edition before 11.3.14, 11.4.x '
                                                  'before 11.4.12, and 11.5.x before 11.5.5 allows Directory '
                                                  'Traversal.'),
                       ('CVE-2018-8825', '2018', 'Google TensorFlow 1.7 and below is affected by: Buffer Overflow. '
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
                                   'leveraging a Visual C++ .NET 2003 application, aka \'Windows Kernel SafeSEH Bypass '
                                   'Vulnerability.\''),
                                  ('CVE-2018-7576', 2018, 'Google TensorFlow 1.6.x and earlier is affected by: Null '
                                   'Pointer Dereference. The type of exploitation is: context-dependent.'),
                                  ('CVE-2018-8825', 2018, 'Google TensorFlow 1.7 and below is affected by: Buffer '
                                   'Overflow. The impact is: execute arbitrary code (local).')]


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    cpe_base = dp.extract_cpe(str(Path(__file__).parent.parent) + '/test/test_resources/test_cpe_extract.xml')
    cpe_base = dp.setup_cpe_table(cpe_base)
    cve_base, summary_base = dp.extract_cve(str(Path(__file__).parent.parent) + '/test/test_resources/'
                                                                                'test_cve_extract.json')
    cve_base, summary_base = dp.setup_cve_table(cve_base, summary_base)
    with meta.DB('test_update.db') as db:
        db.table_manager(query=METADATA['sqlite_queries']['create_cpe_table'].format('cpe_t'))
        db.insert_rows(query=METADATA['sqlite_queries']['insert_cpe'].format('cpe_t'), input_t=cpe_base)
        db.table_manager(query=METADATA['sqlite_queries']['create_cve_table'].format('cve_t'))
        db.table_manager(query=METADATA['sqlite_queries']['create_summary_table'].format('summary_t'))
        db.insert_rows(query=METADATA['sqlite_queries']['insert_cve'].format('cve_t'), input_t=cve_base)
        db.insert_rows(query=METADATA['sqlite_queries']['insert_summary'].format('summary_t'), input_t=summary_base)
    yield None
    try:
        remove('test_update.db')
        remove('test_import.db')
    except OSError:
        pass


def test_import_cpe(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'glob', lambda *_, **__: [str(Path(__file__).parent.parent) + '/test/test_resources/'
                                                                                         'test_cpe_extract.xml'])
        monkey.setattr(dp, 'download_data', lambda *_, **__: None)
        with meta.DB('test_import.db') as db:
            sr.init_rep('test_import.db', False, 1, 2002, 2019, '')
            assert EXPECTED_CPE_OUTPUT.sort() == list(db.select_query('SELECT * FROM cpe_t')).sort()


def test_import_cve(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'glob', lambda *_, **__: [path[0] + '/plugins/analysis/cve_lookup/test/test_resources/'
                                                               'test_cve_extract.json'])
        monkey.setattr(dp, 'download_data', lambda *_, **__: None)
        with meta.DB('test_import.db') as db:
            sr.init_rep('test_import.db', False, 2, 2002, 2019, '')
            assert EXPECTED_CVE_OUTPUT.sort() == list(db.select_query('SELECT * FROM cve_t WHERE '
                                                                      'product=\'ie\'')).sort()
            assert EXPECTED_SUM_OUTPUT.sort() == list(db.select_query('SELECT * FROM summary_t')).sort()


def test_create_cve_update_table(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(dp, 'download_data', lambda *_, **__: None)
        monkey.setattr(sr, 'glob', lambda *_, **__: [path[0] + '/plugins/analysis/cve_lookup/test/test_resources/'
                                                               'nvdcve_test_cve_update.json'])
        with meta.DB('test_update.db') as db:
            sr.create_cve_update_table(db, METADATA, '')
            test_table_exists = list(db.select_query(query=METADATA['test_queries']['test_tables']))
            assert ('temp_feeds',) in test_table_exists
            assert ('temp_sum',) in test_table_exists


def test_update_cve(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(dp, 'download_data', lambda *_, **__: None)
        monkey.setattr(sr, 'glob', lambda *_, **__: [str(Path(__file__).parent.parent) + '/test/test_resources/'
                                                                                         'nvdcve_test_cve_update.json'])
        with meta.DB('test_update.db') as db:
            sr.update_cve(db, METADATA, '')
            assert EXPECTED_UPDATED_CVE_TABLE.sort() == list(db.select_query(query=METADATA['sqlite_queries']
                                                                             ['select_all'].format('cve_t'))).sort()
            if list(db.select_query(METADATA['sqlite_queries']['exist'].format('summary_t'))):
                assert EXPECTED_UPDATED_SUMMARY_TABLE.sort() == list(db.select_query(query=METADATA['sqlite_queries']
                                                                                     ['select_all'].format
                                                                                     ('summary_t'))).sort()


def test_update_cpe(monkeypatch):
    with monkeypatch.context() as monkey:
        monkey.setattr(sr, 'glob', lambda *_, **__: [str(Path(__file__).parent.parent) + '/test/test_resources/'
                                                                                         'test_cpe_update.xml'])
        monkey.setattr(dp, 'download_data', lambda *_, **__: None)
        with meta.DB('test_update.db') as db:
            sr.update_cpe(db, METADATA, '')
            assert EXPECTED_UPDATED_CPE_TABLE.sort() == list(db.select_query(query=METADATA['sqlite_queries']
                                                                             ['select_all'].format('cpe_t'))).sort()


def test_set_repository():
    pass


def test_update_repository():
    pass


def test_init_rep():
    pass

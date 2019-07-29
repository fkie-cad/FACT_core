import sqlite3 as lite
from os import remove

import pytest

from ..internal import meta

BOUND_LIST = ['a', 'micr*osof?t_corp', '*wind§ows 10*', '10.2.4', 'beta\\)1.2', 'sp1', '?en?', '-', '*', '*', '*']
BOUND_VERSION = ['10.2.4']
UNBOUND_VERSION = '10\\.2\\.4'
UNBOUND_LIST = ['a', 'micr\\*osof\\?t_corp', '*wind\\§ows 10*', '10\\.2\\.4', 'beta\\)1\\.2', 'sp1', '?en?', 'NA',
                'ANY', 'ANY', 'ANY']

METADATA = meta.get_meta()


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    try:
        conn = lite.connect('test.db')
        cur = conn.cursor()
        cur.execute(METADATA['sqlite_queries']['test_create'].format('test_table'))
        cur.execute(METADATA['sqlite_queries']['test_insert'].format('test_table'), [23])
        conn.commit()
        conn.close()
    except lite.Error as err:
        exit(err)
    yield None
    try:
        remove('test.db')
    except OSError:
        pass


def test_db_connection():
    with meta.DB('test.db') as db:
        assert db.conn is not None


def test_select_functionality():
    with meta.DB('test.db') as db:
        assert list(db.select_query(query=METADATA['sqlite_queries']['select_all'].format('test_table'))) == [(23,)]


def test_insert_functionality():
    with meta.DB('test.db') as db:
        db.insert_rows(query=METADATA['sqlite_queries']['test_insert'].format('test_table'), input_t=[[34]])
        test_insert_output = list(db.select_query(query=METADATA['sqlite_queries']['select_all'].format('test_table')))
        assert test_insert_output == [(23,), (34,)]


def test_table_manager():
    with meta.DB('test.db') as db:
        db.table_manager(query=METADATA['sqlite_queries']['test_create'].format('test_table_2'))
        assert list(db.select_query(query=METADATA['sqlite_queries']['exist'].format('test_table_2'))) == [('test_table_2',)]
        db.table_manager(query=METADATA['sqlite_queries']['drop'].format('test_table_2'))
        assert list(db.select_query(query=METADATA['sqlite_queries']['exist'].format('test_table_2'))) == []


def test_get_metadata():
    assert list(meta.get_meta().keys()) == ['source_urls', 'sqlite_queries']


def test_analyse_attribute():
    assert meta.analyse_attribute('micr*osof?t_corp') == 'micr\\*osof\\?t_corp'


def test_unbinding():
    assert UNBOUND_LIST == meta.unbinding(BOUND_LIST)
    assert UNBOUND_VERSION == meta.unbinding(BOUND_VERSION)

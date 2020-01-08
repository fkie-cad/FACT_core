import sqlite3 as lite
from os import remove

import pytest

from internal.database_interface import DB, QUERIES


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    try:
        conn = lite.connect('test.db')
        cur = conn.cursor()
        cur.execute(QUERIES['test_create'].format('test_table'))
        cur.execute(QUERIES['test_insert'].format('test_table'), [23])
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
    with DB('test.db') as db:
        assert db.conn is not None
    with pytest.raises(TypeError):
        DB('')


def test_select_functionality():
    with DB('test.db') as db:
        assert list(db.select_query(query=QUERIES['select_all'].format('test_table'))) == [(23,)]


def test_insert_functionality():
    with DB('test.db') as db:
        db.insert_rows(query=QUERIES['test_insert'].format('test_table'), input_t=[[34]])
        test_insert_output = list(db.select_query(query=QUERIES['select_all'].format('test_table')))
        assert test_insert_output == [(23,), (34,)]


def test_table_manager():
    with DB('test.db') as db:
        db.table_manager(query=QUERIES['test_create'].format('test_table_2'))
        assert list(db.select_query(query=QUERIES['exist'].format('test_table_2'))) == [('test_table_2',)]
        db.table_manager(query=QUERIES['drop'].format('test_table_2'))
        assert list(db.select_query(query=QUERIES['exist'].format('test_table_2'))) == []
        db.table_manager('')

import logging
import sqlite3
import sys
from contextlib import suppress
from os import remove
from pathlib import Path

import pytest

TEST_DB_PATH = 'test.db'
TEST_QUERIES = {
    'test_create': 'CREATE TABLE IF NOT EXISTS {} (x INTEGER)',
    'test_create_update': 'CREATE TABLE IF NOT EXISTS {} (cve_id TEXT NOT NULL, year INTEGER NOT NULL)',
    'test_insert': 'INSERT INTO {} (x) VALUES (?)',
    'test_insert_cve_id': 'INSERT INTO {} (cve_id, year) VALUES (?, ?)',
}

try:
    from ..internal.database_interface import QUERIES, DatabaseInterface
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from database_interface import QUERIES, DatabaseInterface


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    try:
        connection = sqlite3.connect(TEST_DB_PATH)
        cursor = connection.cursor()
        cursor.execute(TEST_QUERIES['test_create'].format('test_table'))
        cursor.execute(TEST_QUERIES['test_insert'].format('test_table'), [23])
        connection.commit()
        connection.close()
    except sqlite3.Error as error:
        logging.error(f'[cve_lookup]: could not connect to test database: {type(error).__name__} {error}')
    yield
    with suppress(OSError):
        remove(TEST_DB_PATH)


def test_db_connection():
    with DatabaseInterface(TEST_DB_PATH) as db:
        assert db.connection is not None


def test_select_functionality():
    with DatabaseInterface(TEST_DB_PATH) as db:
        assert list(db.fetch_multiple(query=QUERIES['select_all'].format('test_table'))) == [(23,)]


def test_insert_functionality():
    with DatabaseInterface(TEST_DB_PATH) as db:
        db.insert_rows(TEST_QUERIES['test_insert'].format('test_table'), [(34,)])
        test_insert_output = list(db.fetch_multiple(query=QUERIES['select_all'].format('test_table')))
        assert test_insert_output == [(23,), (34,)]


def test_execute_query():
    with DatabaseInterface(TEST_DB_PATH) as db:
        db.execute_query(query=TEST_QUERIES['test_create'].format('test_table_2'))
        assert list(db.fetch_multiple(query=QUERIES['exist'].format('test_table_2'))) == [('test_table_2',)]
        db.execute_query(query=QUERIES['drop'].format('test_table_2'))
        assert list(db.fetch_multiple(query=QUERIES['exist'].format('test_table_2'))) == []

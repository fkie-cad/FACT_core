import sqlite3 as lite
from os import remove

import pytest

from ..internal import meta

EXPECTED_METADATA_OUTPUT = {'test_key': 'test_value'}
# the input and expected result for the unbinding function
BOUND_LIST = ['a', 'micr*osof?t_corp', '*wind§ows 10*', '10.2.4', 'beta\\)1.2', 'sp1', '?en?', '-', '*', '*', '*']
BOUND_VERSION = ['10.2.4']
UNBOUND_VERSION = '10\\.2\\.4'
UNBOUND_LIST = ['a', 'micr\\*osof\\?t_corp', '*wind\\§ows 10*', '10\\.2\\.4', 'beta\\)1\\.2', 'sp1', '?en?', 'NA',
                'ANY', 'ANY', 'ANY']
EXPECTED_SELECT_OUTPUT = [('Michael', 'Myers', 23)]
EXPECTED_INSERT_OUTPUT = [('Michael', 'Myers', 23), ('Max', 'Mustermann', 34)]
EXPECTED_CREATE_OUTPUT = ['test1', 'test2']
EXPECTED_DROP_OUTPUT = ['test1']

METADATA = meta.get_meta()


@pytest.fixture(scope='module', autouse=True)
def setup() -> None:
    try:
        conn = lite.connect('test.db')
        cur = conn.cursor()
        cur.execute(METADATA['test_queries']['setup_test_table'])
        cur.execute(METADATA['test_queries']['setup_test_row'], ('Michael', 'Myers', 23))
        conn.commit()
        conn.close()
    except lite.Error as err:
        exit(err)
    yield None
    try:
        remove('test.db')
    except OSError:
        pass


@pytest.mark.skip(reason='whole test module is broken')
def test_db_connection():
    with meta.DB('test.db') as db:
        assert db.conn is not None


@pytest.mark.skip(reason='whole test module is broken')
def test_select_functionality():
    with meta.DB('test.db') as db:
        test_select_output = list(db.select_query(query=METADATA['test_queries']['test_select']))
        assert test_select_output == EXPECTED_SELECT_OUTPUT


@pytest.mark.skip(reason='whole test module is broken')
def test_insert_functionality():
    with meta.DB('test.db') as db:
        db.insert_rows(query=METADATA['test_queries']['test_insert'], input_t=[['Max', 'Mustermann', 34]])
        test_insert_output = list(db.select_query(query=METADATA['test_queries']['test_select']))
        assert test_insert_output == EXPECTED_INSERT_OUTPUT


@pytest.mark.skip(reason='whole test module is broken')
def test_table_manager():
    test_create_output = list()
    test_drop_output = list()
    with meta.DB('test.db') as db:
        db.table_manager(query=METADATA['test_queries']['test_create'])
        for el in list(db.select_query(query=METADATA['test_queries']['test_tables'])):
            test_create_output.append(el[0])
        assert test_create_output == EXPECTED_CREATE_OUTPUT
        db.table_manager(query=METADATA['test_queries']['test_drop'])
        for el in list(db.select_query(query=METADATA['test_queries']['test_tables'])):
            test_drop_output.append(el[0])
        assert test_drop_output == EXPECTED_DROP_OUTPUT


@pytest.mark.skip(reason='whole test module is broken')
def test_get_metadata():
    test_metadata_output = meta.get_meta()
    assert test_metadata_output == EXPECTED_METADATA_OUTPUT


@pytest.mark.skip(reason='whole test module is broken')
def test_analyse_attribute():
    pass


@pytest.mark.skip(reason='whole test module is broken')
def test_unbinding():
    assert UNBOUND_LIST == meta.unbinding(BOUND_LIST)
    assert UNBOUND_VERSION == meta.unbinding(BOUND_VERSION)

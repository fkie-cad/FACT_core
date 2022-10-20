import logging
import sys
from contextlib import contextmanager, suppress
from pathlib import Path
from sqlite3 import Error as SqliteException
from sqlite3 import connect

try:
    from ..internal.helper_functions import get_field_names, get_field_string
except (ImportError, SystemError):
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from helper_functions import get_field_names, get_field_string

DB_PATH = str(Path(__file__).parent / 'cve_cpe.db')

CPE_DB_FIELDS = [
    ('cpe_id', 'TEXT'),
    ('part', 'TEXT'),
    ('vendor', 'TEXT'),
    ('product', 'TEXT'),
    ('version', 'TEXT'),
    ('\'update\'', 'TEXT'),
    ('edition', 'TEXT'),
    ('language', 'TEXT'),
    ('sw_edition', 'TEXT'),
    ('target_sw', 'TEXT'),
    ('target_hw', 'TEXT'),
    ('other', 'TEXT'),
]
CVE_DB_FIELDS = [
    ('cve_id', 'TEXT'),
    ('year', 'INTEGER'),
    ('cpe_id', 'TEXT'),
    ('cvss_v2_score', 'TEXT'),
    ('cvss_v3_score', 'TEXT'),
    ('part', 'TEXT'),
    ('vendor', 'TEXT'),
    ('product', 'TEXT'),
    ('version', 'TEXT'),
    ('\'update\'', 'TEXT'),
    ('edition', 'TEXT'),
    ('language', 'TEXT'),
    ('sw_edition', 'TEXT'),
    ('target_sw', 'TEXT'),
    ('target_hw', 'TEXT'),
    ('other', 'TEXT'),
    ('version_start_including', 'TEXT'),
    ('version_start_excluding', 'TEXT'),
    ('version_end_including', 'TEXT'),
    ('version_end_excluding', 'TEXT'),
]
CVE_SUMMARY_DB_FIELDS = [
    ('cve_id', 'TEXT'),
    ('year', 'INTEGER'),
    ('summary', 'TEXT'),
    ('cvss_v2_score', 'TEXT'),
    ('cvss_v3_score', 'TEXT'),
]

TABLE_CREATION_COMMAND = 'CREATE TABLE IF NOT EXISTS {{}} ({})'
TABLE_INSERT_COMMAND = 'INSERT INTO {{}} ({}) VALUES ({})'

QUERIES = {
    'cpe_lookup': 'SELECT DISTINCT vendor, product, version FROM cpe_table',
    'create_cpe_table': TABLE_CREATION_COMMAND.format(get_field_string(CPE_DB_FIELDS)),
    'create_cve_table': TABLE_CREATION_COMMAND.format(get_field_string(CVE_DB_FIELDS)),
    'create_summary_table': TABLE_CREATION_COMMAND.format(get_field_string(CVE_SUMMARY_DB_FIELDS)),
    'cve_lookup': 'SELECT cve_id, vendor, product, version, cvss_v2_score, cvss_v3_score, version_start_including, '
    'version_start_excluding, version_end_including, version_end_excluding FROM cve_table',
    'delete_outdated': 'DELETE FROM {} WHERE cve_id IN (SELECT cve_id FROM {})',
    'drop': 'DROP TABLE IF EXISTS {}',
    'exist': 'SELECT name FROM sqlite_master WHERE type=\'table\' AND name=\'{}\'',
    'extract_relevant': 'SELECT * FROM {} AS new WHERE new.year IN (SELECT distinct(year) FROM {})',
    'get_years_from_cve': 'SELECT DISTINCT year FROM cve_table',
    'insert_cpe': TABLE_INSERT_COMMAND.format(get_field_names(CPE_DB_FIELDS), ', '.join(['?'] * len(CPE_DB_FIELDS))),
    'insert_cve': TABLE_INSERT_COMMAND.format(get_field_names(CVE_DB_FIELDS), ', '.join(['?'] * len(CVE_DB_FIELDS))),
    'insert_summary': TABLE_INSERT_COMMAND.format(
        get_field_names(CVE_SUMMARY_DB_FIELDS), ', '.join(['?'] * len(CVE_SUMMARY_DB_FIELDS))
    ),
    'select_all': 'SELECT * FROM {}',
    'summary_lookup': 'SELECT cve_id, summary, cvss_v2_score, cvss_v3_score FROM summary_table',
}


class DatabaseInterface:
    '''
    class to provide connections to a sqlite database and allows to operate on it
    '''

    def __init__(self, db_path: str = DB_PATH):
        self.connection = None
        try:
            self.connection = connect(db_path)
        except SqliteException:
            logging.error('Could not connect to CPE database.')
            raise

    def execute_query(self, query: str):
        with self.get_cursor() as cursor:
            cursor.execute(query)

    def fetch_multiple(self, query: str):
        with self.get_cursor() as cursor:
            cursor.execute(query)
            while True:
                result_batch = cursor.fetchmany(1000)
                if not result_batch:
                    break
                yield from result_batch

    def fetch_one(self, query: str):
        with self.get_cursor() as cursor:
            cursor.execute(query)
            return cursor.fetchone()

    def insert_rows(self, query: str, input_data: list):
        with self.get_cursor() as cursor:
            wrong_entries = {e for e in input_data if len(e) != query.count('?')}
            if wrong_entries:
                logging.warning(f'Ignoring possibly wrong entries: {[e[2] for e in wrong_entries]}')
            cursor.executemany(query, list(set(input_data) - wrong_entries))
            self.connection.commit()

    @contextmanager
    def get_cursor(self):
        cursor = None
        try:
            cursor = self.connection.cursor()
            yield cursor
        except SqliteException as error:
            logging.error(f'[cve_lookup]: Encountered error while accessing DB: {error}', exc_info=True)
        finally:
            with suppress(AttributeError, SqliteException):
                cursor.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection:
            with suppress(SqliteException):
                self.connection.close()

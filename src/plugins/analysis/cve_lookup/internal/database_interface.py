import logging
from contextlib import suppress
from pathlib import Path
from sqlite3 import Error as SqliteException
from sqlite3 import connect

DB_PATH = str(Path(__file__).parent / 'cve_cpe.db')

QUERIES = {
    "cpe_lookup": "SELECT DISTINCT vendor, product, version FROM cpe_table",
    "create_cpe_table": "CREATE TABLE IF NOT EXISTS {} (cpe_id TEXT NOT NULL, part TEXT NOT NULL, vendor TEXT NOT NULL,"
                        " product TEXT NOT NULL, version TEXT NOT NULL, 'update' TEXT NOT NULL, edition TEXT NOT NULL, "
                        "language TEXT NOT NULL, sw_edition TEXT NOT NULL, target_sw TEXT NOT NULL, target_hw TEXT NOT "
                        "NULL, other TEXT NOT NULL)",
    "create_cve_table": "CREATE TABLE IF NOT EXISTS {} (cve_id TEXT NOT NULL, year INTEGER NOT NULL, cpe_id TEXT NOT "
                        "NULL, part TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL, "
                        "'update' TEXT NOT NULL, edition TEXT NOT NULL, language TEXT NOT NULL, sw_edition TEXT NOT "
                        "NULL, target_sw TEXT NOT NULL, target_hw TEXT NOT NULL, other TEXT NOT NULL)",
    "create_summary_table": "CREATE TABLE IF NOT EXISTS {} (cve_id TEXT NOT NULL, year INTEGER NOT NULL, summary TEXT NOT NULL )",
    "cve_lookup": "SELECT cve_id, vendor, product, version FROM cve_table",
    "delete_outdated": "DELETE FROM {} WHERE cve_id IN (SELECT cve_id FROM {})",
    "drop": "DROP TABLE IF EXISTS {}",
    "exist": "SELECT name FROM sqlite_master WHERE type='table' AND name='{}'",
    "extract_relevant": "SELECT * FROM {} AS new WHERE new.year IN (SELECT distinct(year) FROM {})",
    "get_years_from_cve": "SELECT DISTINCT year FROM cve_table",
    "insert_cpe": "INSERT INTO {} (cpe_id, part, vendor, product, version, 'update', edition, language, sw_edition, "
                  "target_sw, target_hw, other) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    "insert_cve": "INSERT INTO {} (cve_id, year, cpe_id, part, vendor, product, version, 'update', edition, language, "
                  "sw_edition, target_sw, target_hw, other) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    "insert_summary": "INSERT INTO {} (cve_id, year, summary) VALUES (?, ?, ?)",
    "select_all": "SELECT * FROM {}",
    "summary_lookup": "SELECT cve_id, summary FROM summary_table",
    "test_create": "CREATE TABLE IF NOT EXISTS {} (x INTEGER)",
    "test_create_update": "CREATE TABLE IF NOT EXISTS {} (cve_id TEXT NOT NULL, year INTEGER NOT NULL)",
    "test_insert": "INSERT INTO {} (x) VALUES (?)",
    "test_insert_cve_id": "INSERT INTO {} (cve_id, year) VALUES (?, ?)"
}


class DatabaseInterface:
    '''
    class to provide connections to a sqlite database and allows to operate on it
    '''
    def __init__(self, db_path: str = DB_PATH):
        self.connection = None
        self.cursor = None
        if not db_path.endswith('.db') and isinstance(db_path, str):
            raise TypeError('Input must be string and end on \'.db\'')
        try:
            self.connection = connect(db_path)
        except SqliteException as exception:
            logging.warning('Could not connect to CPE database: {} {}'.format(type(exception).__name__, exception))
            raise exception

    def table_manager(self, query: str):
        try:
            self.cursor = self.connection.cursor()
            self.cursor.execute(query)
        finally:
            self.cursor.close()

    def select_query(self, query: str):
        try:
            self.cursor = self.connection.cursor()
            self.cursor.execute(query)
            while True:
                outputs = self.cursor.fetchmany(10000)
                if not outputs:
                    break
                for output in outputs:
                    yield output
        finally:
            self.cursor.close()

    def select_single(self, query: str) -> tuple:
        return list(self.select_query(query))[0]

    def insert_rows(self, query: str, input_data: list):
        try:
            self.cursor = self.connection.cursor()
            self.cursor.executemany(query, input_data)
            self.connection.commit()
        finally:
            self.cursor.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.connection:
            with suppress(SqliteException):
                self.connection.close()

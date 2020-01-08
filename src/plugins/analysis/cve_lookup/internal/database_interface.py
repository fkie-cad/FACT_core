from sqlite3 import Error, connect

DB_NAME = 'cve_cpe.db'

QUERIES = {
    "cpe_lookup": "SELECT DISTINCT vendor, product, version FROM cpe_table",
    "create_cpe_table": "CREATE TABLE IF NOT EXISTS {} (cpe_id TEXT NOT NULL, part TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL, 'update' TEXT NOT NULL, edition TEXT NOT NULL, language TEXT NOT NULL, sw_edition TEXT NOT NULL, target_sw TEXT NOT NULL, target_hw TEXT NOT NULL, other TEXT NOT NULL)",
    "create_cve_table": "CREATE TABLE IF NOT EXISTS {} (cve_id TEXT NOT NULL, year INTEGER NOT NULL, cpe_id TEXT NOT NULL, part TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL, version TEXT NOT NULL, 'update' TEXT NOT NULL, edition TEXT NOT NULL, language TEXT NOT NULL, sw_edition TEXT NOT NULL, target_sw TEXT NOT NULL, target_hw TEXT NOT NULL, other TEXT NOT NULL)",
    "create_summary_table": "CREATE TABLE IF NOT EXISTS {} (cve_id TEXT NOT NULL, year INTEGER NOT NULL, summary TEXT NOT NULL )",
    "cve_lookup": "SELECT cve_id, vendor, product, version FROM cve_table",
    "delete_outdated": "DELETE FROM {} WHERE cve_id IN (SELECT cve_id FROM {})",
    "drop": "DROP TABLE IF EXISTS {}",
    "exist": "SELECT name FROM sqlite_master WHERE type='table' AND name='{}'",
    "extract_relevant": "SELECT * FROM {} AS new WHERE new.year IN (SELECT distinct(year) FROM {})",
    "get_years_from_cve": "SELECT DISTINCT year FROM cve_table",
    "insert_cpe": "INSERT INTO {} (cpe_id, part, vendor, product, version, 'update', edition, language, sw_edition, target_sw, target_hw, other) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    "insert_cve": "INSERT INTO {} (cve_id, year, cpe_id, part, vendor, product, version, 'update', edition, language, sw_edition, target_sw, target_hw, other) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    "insert_summary": "INSERT INTO {} (cve_id, year, summary) VALUES (?, ?, ?)",
    "select_all": "SELECT * FROM {}",
    "summary_lookup": "SELECT cve_id, summary FROM summary_table",
    "test_create": "CREATE TABLE IF NOT EXISTS {} (x INTEGER)",
    "test_create_update": "CREATE TABLE IF NOT EXISTS {} (cve_id TEXT NOT NULL, year INTEGER NOT NULL)",
    "test_insert": "INSERT INTO {} (x) VALUES (?)",
    "test_insert_cve_id": "INSERT INTO {} (cve_id, year) VALUES (?, ?)"
  }


class DB:
    '''
    class to provide connections to a sqlite database and allows to operate on it
    '''
    def __init__(self, db_loc: str):
        self.conn = None
        self.cur = None
        if db_loc.endswith('.db') and isinstance(db_loc, str):
            try:
                self.conn = connect(db_loc)
            except Error as err:
                raise err
        else:
            raise TypeError('Input must be string and end on \'.db\'')

    def table_manager(self, query: str):
        try:
            self.cur = self.conn.cursor()
            self.cur.execute(query)
        except Error as err:
            raise err
        finally:
            self.cur.close()

    def select_query(self, query: str):
        try:
            self.cur = self.conn.cursor()
            self.cur.execute(query)
            while True:
                outputs = self.cur.fetchmany(10000)
                if not outputs:
                    break
                else:
                    for output in outputs:
                        yield output
        except Error as err:
            raise err
        finally:
            self.cur.close()

    def select_single(self, query: str) -> tuple:
        return list(self.select_query(query))[0]

    def insert_rows(self, query: str, input_t: list):
        try:
            self.cur = self.conn.cursor()
            self.cur.executemany(query, input_t)
            self.conn.commit()
        except Error as err:
            raise err
        finally:
            self.cur.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            try:
                self.conn.close()
            except Error as err:
                raise err

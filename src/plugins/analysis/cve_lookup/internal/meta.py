from json import load
from pathlib import Path
from re import finditer, match
from sqlite3 import Error, connect

DB_NAME = 'cve_cpe.db'


class DB:
    '''
    class to provide connections to a sqlite database and allows to operate on it
    '''
    def __init__(self, db_loc: str):
        self.conn = None
        self.cur = None
        if db_loc:
            try:
                self.conn = connect(db_loc)
            except Error as err:
                raise err

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


def get_meta() -> dict:
    meta_path = str(Path(__file__).parent / 'metadata.json')
    try:
        with open(meta_path) as meta:
            metadata = load(meta)
    except EnvironmentError as err:
        raise err

    return metadata


def analyse_attribute(attribute: str) -> str:
    # a counter is incremented every time an escape character is added because it alters the string length
    counter = 0
    for characters in finditer(r'[^.]((?<!\\)[*?])[^.]|((?<!\\)[^a-zA-Z0-9\s?*_\\])', attribute):
        if -1 == characters.span(1)[0]:
            start = characters.span(2)[0] + counter
        else:
            start = characters.span(1)[0] + counter
        if start:
            attribute = attribute[:start] + '\\' + attribute[start:]
            counter += 1

    return attribute


def unbinding(attributes: list):
    for idx, attr in enumerate(attributes):
        if attr == '*':
            attributes[idx] = 'ANY'
        elif attr == '-':
            attributes[idx] = 'NA'
        # if there are no non-alphanumeric characters apart from underscore and escaped colon, continue
        elif not match(r'^.*[^a-zA-Z0-9_\\:].*$', attr):
            continue
        else:
            attributes[idx] = analyse_attribute(attr)

    return attributes if len(attributes) > 1 else attributes[0]

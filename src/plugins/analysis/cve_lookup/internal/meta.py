from json import load
from os.path import isfile
from re import match, finditer
from sqlite3 import connect, Error
from sys import path


class DB:
    '''
    class to provide connections to a sqlite database and allows to operate on it
    '''
    def __init__(self, db_loc: str = None):
        self.conn = None
        self.cur = None
        if db_loc:
            try:
                self.conn = connect(db_loc)
            except Error as err:
                raise err

    def table_manager(self, query: str = None) -> None:
        '''
        Covers all operation where the database is altered and nothing is returned. This includes CREATE and DROP
        :param query: query for creating or dropping tables
        '''
        try:
            self.cur = self.conn.cursor()
            self.cur.execute(query)
        except Error as err:
            raise err
        finally:
            self.cur.close()

    def select_query(self, query: str = None):
        '''

        :param query: query for selecting multiple rows from a table
        :return: contains generator object with returned rows
        '''
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

    def select_single(self, query: str = None) -> tuple:
        '''

        :param query: query for selecting a single row from a table
        :return: tuple containing one row
        '''
        return list(self.select_query(query))[0]

    def insert_rows(self, query: str = None, input_t: list = None) -> None:
        try:
            self.cur = self.conn.cursor()
            self.cur.executemany(query, input_t)
            self.conn.commit()
        except Error as err:
            raise err
        finally:
            self.cur.close()

    def __enter__(self):
        '''
        :return: itself
        '''
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            try:
                self.conn.close()
            except Error as err:
                raise err


def get_meta(specified_file: str = None) -> dict:
    '''
    Retrieves data from json file
    :param specified_file: path to specified json file
    :return: json content in dictionary
    '''
    if not specified_file:
        meta_path = path[0] + '/plugins/analysis/cve_lookup/internal/metadata.json'
    else:
        meta_path = specified_file
        if not isfile(meta_path):
            exit(1)
    try:
        with open(meta_path) as meta:
            metadata = load(meta)
    except EnvironmentError as err:
        raise err

    return metadata


def analyse_attribute(attribute: str) -> str:
    '''
    Unbinds a CPE attribute by following the CPE naming convention
    find all asterisks (*) and question marks and escape them if they are not at the end or beginning of the
    string or already escaped.
    escape all other non alphanumeric character except for *,?,_ ,\\ and whitespaces
    :param attribute: has to be unbound
    :return: unbound string
    '''
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
    '''
    unbinds a attributes from a CPE format string to the corresponding WFN format
    :param attributes: list of attributes from CPE ID
    :return: list of attributes conforming to CPE naming convention
    '''
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

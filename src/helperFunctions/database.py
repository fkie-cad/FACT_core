import logging
import re
import sys
from typing import Any, Generic, Type, TypeVar

DatabaseInterface = TypeVar('DatabaseInterface')


class ConnectTo(Generic[DatabaseInterface]):
    def __init__(self, connected_interface: Type[DatabaseInterface], config):
        self.interface = connected_interface
        self.config = config

    def __enter__(self) -> DatabaseInterface:
        self.connection = self.interface(self.config)
        return self.connection

    def __exit__(self, *args):
        self.connection.shutdown()


def is_sanitized_entry(entry: Any) -> bool:
    '''
    Check a database entry if it was sanitized (meaning the database entry was too large for the MongoDB database and
    was swapped to the file system).

    :param entry: A database entry.
    :return: `True` if the entry is sanitized and `False` otherwise.
    '''
    try:
        if re.search(r'_[0-9a-f]{64}_[0-9]+', entry) is None:
            return False
        return True
    except TypeError:  # DB entry has type other than string (e.g. integer or float)
        return False
    except Exception as e_type:
        logging.error('Could not determine entry sanitization state: {} {}'.format(sys.exc_info()[0].__name__, e_type))
        return False

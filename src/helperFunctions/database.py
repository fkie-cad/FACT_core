import re
from configparser import ConfigParser
from typing import Any, Generic, Type, TypeVar

DatabaseInterface = TypeVar('DatabaseInterface')


class ConnectTo(Generic[DatabaseInterface]):
    '''
    Open a database connection using the interface passed to the constructor. Intended to be used as a context manager.

    :param connected_interface: A database interface from the `storage` module (e.g. `FrontEndDbInterface`)
    :param config: A FACT configuration.

    :Example:

        .. code-block:: python

           with ConnectTo(FrontEndDbInterface, self.config) as connection:
                query = connection.firmwares.find({})
    '''
    def __init__(self, connected_interface: Type[DatabaseInterface], config: ConfigParser):
        self.interface = connected_interface
        self.config = config
        self.connection = None

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

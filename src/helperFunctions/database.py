from configparser import ConfigParser
from contextlib import contextmanager
from typing import ContextManager, Generic, Type, TypeVar

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
        pass


@contextmanager
def get_shared_session(database: DatabaseInterface) -> ContextManager[DatabaseInterface]:
    with database.get_read_only_session():
        yield database

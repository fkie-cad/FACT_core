from typing import Generic, Type, TypeVar

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

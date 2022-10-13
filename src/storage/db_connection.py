from configparser import ConfigParser
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from storage.schema import Base


class DbConnection:
    def __init__(self, config: ConfigParser, user: str = None, password: str = None, db_name: Optional[str] = None, **kwargs):
        self.base = Base
        self.config = config
        address = config.get('data-storage', 'postgres-server')
        port = config.get('data-storage', 'postgres-port')
        user = self.config.get('data-storage', user)
        password = self.config.get('data-storage', password)
        database = db_name if db_name else config.get('data-storage', 'postgres-database')
        engine_url = f'postgresql://{user}:{password}@{address}:{port}/{database}'
        self.engine = create_engine(engine_url, pool_size=100, future=True, **kwargs)
        self.session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support

    def create_tables(self):  # pylint: disable=no-self-use
        raise Exception('Only the admin connection may create tables')


class ReadOnlyConnection(DbConnection):
    def __init__(self, config: ConfigParser, user: str = 'postgres-ro-user', password: str = 'postgres-ro-pw', **kwargs):
        super().__init__(config, user, password, **kwargs)


class ReadWriteConnection(DbConnection):
    def __init__(self, config: ConfigParser, user: str = 'postgres-rw-user', password: str = 'postgres-rw-pw', **kwargs):
        super().__init__(config, user, password, **kwargs)


class ReadWriteDeleteConnection(DbConnection):
    def __init__(self, config: ConfigParser, user: str = 'postgres-del-user', password: str = 'postgres-del-pw', **kwargs):
        super().__init__(config, user, password, **kwargs)


class AdminConnection(DbConnection):
    def __init__(self, config: ConfigParser, user: str = 'postgres-admin-user', password: str = 'postgres-admin-pw', **kwargs):
        super().__init__(config, user, password, **kwargs)

    def create_tables(self):
        self.base.metadata.create_all(self.engine)

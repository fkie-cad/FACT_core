from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from storage.schema import Base

from config import cfg


class DbConnection:
    def __init__(self, user: str = None, password: str = None, db_name: Optional[str] = None, **kwargs):
        self.base = Base

        address = cfg.data_storage.postgres_server
        port = cfg.data_storage.postgres_port
        user = getattr(cfg.data_storage, user)
        password = getattr(cfg.data_storage, password)

        database = db_name if db_name else cfg.data_storage.postgres_database
        engine_url = f'postgresql://{user}:{password}@{address}:{port}/{database}'
        self.engine = create_engine(engine_url, pool_size=100, future=True, **kwargs)
        self.session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support

    def create_tables(self):  # pylint: disable=no-self-use
        raise Exception('Only the admin connection may create tables')


class ReadOnlyConnection(DbConnection):
    def __init__(self, user: str = 'postgres_ro_user', password: str = 'postgres_ro_pw', **kwargs):
        super().__init__(user, password, **kwargs)


class ReadWriteConnection(DbConnection):
    def __init__(self, user: str = 'postgres_rw_user', password: str = 'postgres_rw_pw', **kwargs):
        super().__init__(user, password, **kwargs)


class ReadWriteDeleteConnection(DbConnection):
    def __init__(self, user: str = 'postgres_del_user', password: str = 'postgres_del_pw', **kwargs):
        super().__init__(user, password, **kwargs)


class AdminConnection(DbConnection):
    def __init__(self, user: str = 'postgres_admin_user', password: str = 'postgres_admin_pw', **kwargs):
        super().__init__(user, password, **kwargs)

    def create_tables(self):
        self.base.metadata.create_all(self.engine)

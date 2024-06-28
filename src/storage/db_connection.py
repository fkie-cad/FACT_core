from __future__ import annotations

from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

import config
from storage.schema import Base


class DbConnection:
    def __init__(
        self, user: Optional[str] = None, password: Optional[str] = None, db_name: str | None = None, **kwargs
    ):
        self.base = Base

        address = config.common.postgres.server
        if address in ('localhost', '127.0.0.1', '::1'):
            # local postgres => connect through UNIX domain socket (faster than TCP)
            address = '/var/run/postgresql'
        port = config.common.postgres.port
        user = getattr(config.common.postgres, user)
        password = getattr(config.common.postgres, password)

        database = db_name if db_name else config.common.postgres.database
        engine_url = URL.create(
            'postgresql',
            username=user,
            password=password,
            host=address,
            port=port,
            database=database,
        )
        self.engine = create_engine(engine_url, pool_size=100, future=True, **kwargs)
        self.session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support

    def create_tables(self):
        raise Exception('Only the admin connection may create tables')


class ReadOnlyConnection(DbConnection):
    def __init__(self, user: str = 'ro_user', password: str = 'ro_pw', **kwargs):
        super().__init__(user, password, **kwargs)


class ReadWriteConnection(DbConnection):
    def __init__(self, user: str = 'rw_user', password: str = 'rw_pw', **kwargs):
        super().__init__(user, password, **kwargs)


class ReadWriteDeleteConnection(DbConnection):
    def __init__(self, user: str = 'del_user', password: str = 'del_pw', **kwargs):
        super().__init__(user, password, **kwargs)


class AdminConnection(DbConnection):
    def __init__(self, user: str = 'admin_user', password: str = 'admin_pw', **kwargs):
        super().__init__(user, password, **kwargs)

    def create_tables(self):
        self.base.metadata.create_all(self.engine)

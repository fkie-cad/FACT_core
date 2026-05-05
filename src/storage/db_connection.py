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
        self._init_user = user
        self._init_password = password
        self._init_db_name = db_name or config.common.postgres.database
        self._init_kwargs = kwargs
        self._setup_connection()

    def _setup_connection(self):
        self.base = Base

        address = config.common.postgres.server
        if address in ('localhost', '127.0.0.1', '::1'):
            # local postgres => connect through UNIX domain socket (faster than TCP)
            address = '/var/run/postgresql'

        engine_url = URL.create(
            'postgresql',
            username=self._init_user,
            password=self._init_password,
            host=address,
            port=config.common.postgres.port,
            database=self._init_db_name if self._init_db_name else config.common.postgres.database,
        )
        self.engine = create_engine(engine_url, pool_size=100, future=True, **self._init_kwargs)
        self.session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support

    def __getstate__(self):
        state = self.__dict__.copy()
        # cannot be pickled
        del state['base']
        del state['engine']
        del state['session_maker']
        return state

    def __setstate__(self, state: dict):
        self.__dict__.update(state)
        self._setup_connection()  # reconnect in the child process

    def create_tables(self):
        raise Exception('Only the admin connection may create tables')


class ReadOnlyConnection(DbConnection):
    def __init__(self, **kwargs):
        super().__init__(config.common.postgres.ro_user, config.common.postgres.ro_pw, **kwargs)


class ReadWriteConnection(DbConnection):
    def __init__(self, **kwargs):
        super().__init__(config.common.postgres.rw_user, config.common.postgres.rw_pw, **kwargs)


class ReadWriteDeleteConnection(DbConnection):
    def __init__(self, **kwargs):
        super().__init__(config.common.postgres.del_user, config.common.postgres.del_pw, **kwargs)


class AdminConnection(DbConnection):
    def __init__(self, **kwargs):
        super().__init__(config.common.postgres.admin_user, config.common.postgres.admin_pw, **kwargs)

    def create_tables(self):
        self.base.metadata.create_all(self.engine)

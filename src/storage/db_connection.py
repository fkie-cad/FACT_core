from __future__ import annotations

import contextlib
import os
from typing import TYPE_CHECKING

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker

import config
from storage.schema import Base

if TYPE_CHECKING:
    from sqlalchemy.engine import Engine

# Registry of all created engines so they can be disposed in forked child processes.
_engines: set[Engine] = set()


def _dispose_engines_after_fork() -> None:
    """
    SQLAlchemy engines are not fork-safe: the child inherits the parent's C-extension state and shared sockets.
    Calling ``dispose(close=False)`` replaces the pool with a fresh one while leaving the parent's connections intact.
    """
    for engine in _engines:
        with contextlib.suppress(Exception):
            engine.dispose(close=False)


os.register_at_fork(after_in_child=_dispose_engines_after_fork)


class DbConnection:
    def __init__(self, user: str | None = None, password: str | None = None, db_name: str | None = None, **kwargs):
        self.base = Base

        address = config.common.postgres.server
        if address in ('localhost', '127.0.0.1', '::1'):
            # local postgres => connect through UNIX domain socket (faster than TCP)
            address = '/var/run/postgresql'
        port = config.common.postgres.port

        database = db_name or config.common.postgres.database
        engine_url = URL.create(
            'postgresql',
            username=user,
            password=password,
            host=address,
            port=port,
            database=database,
        )
        self.engine = create_engine(engine_url, pool_size=100, future=True, **kwargs)
        _engines.add(self.engine)
        self.session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support

    def create_tables(self) -> None:
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

    def create_tables(self) -> None:
        self.base.metadata.create_all(self.engine)

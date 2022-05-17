import logging
from configparser import ConfigParser
from contextlib import contextmanager
from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from storage.schema import Base


class DbInterfaceError(Exception):
    pass


class ReadOnlyDbInterface:
    def __init__(self, config: ConfigParser, db_name: Optional[str] = None, **kwargs):
        self.base = Base
        self.config = config
        address = config.get('data-storage', 'postgres-server')
        port = config.get('data-storage', 'postgres-port')
        database = db_name if db_name else config.get('data-storage', 'postgres-database')
        user, password = self._get_user()
        engine_url = f'postgresql://{user}:{password}@{address}:{port}/{database}'
        self.engine = create_engine(engine_url, pool_size=100, future=True, **kwargs)
        self._session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support
        self.ro_session = None

    def _get_user(self):
        # overridden by interfaces with different privileges
        user = self.config.get('data-storage', 'postgres-ro-user')
        password = self.config.get('data-storage', 'postgres-ro-pw')
        return user, password

    def create_tables(self):
        self.base.metadata.create_all(self.engine)

    @contextmanager
    def get_read_only_session(self) -> Session:
        if self.ro_session is not None:
            yield self.ro_session
            return
        self.ro_session: Session = self._session_maker()
        try:
            yield self.ro_session
        except SQLAlchemyError as err:
            message = 'Database error when trying to read from the database'
            logging.exception(f'{message}: {err}')
            raise DbInterfaceError(message) from err
        finally:
            self.ro_session.invalidate()
            self.ro_session = None


class ReadWriteDbInterface(ReadOnlyDbInterface):

    def _get_user(self):
        user = self.config.get('data-storage', 'postgres-rw-user')
        password = self.config.get('data-storage', 'postgres-rw-pw')
        return user, password

    @contextmanager
    def get_read_write_session(self) -> Session:
        session = self._session_maker()
        try:
            yield session
            session.commit()
        except (SQLAlchemyError, DbInterfaceError) as err:
            message = 'Database error when trying to write to the database'
            logging.exception(f'{message}: {err}')
            session.rollback()
            raise DbInterfaceError(message) from err
        finally:
            session.invalidate()

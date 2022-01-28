import logging
from configparser import ConfigParser
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from storage.schema import Base


class DbInterfaceError(Exception):
    pass


class ReadOnlyDbInterface:
    def __init__(self, config: ConfigParser):
        self.base = Base
        address = config.get('data_storage', 'postgres_server')
        port = config.get('data_storage', 'postgres_port')
        database = config.get('data_storage', 'postgres_database')
        user, password = self._get_user(config)
        engine_url = f'postgresql://{user}:{password}@{address}:{port}/{database}'
        self.engine = create_engine(engine_url, pool_size=100, pool_recycle=60, future=True)
        self._session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support
        self.ro_session = None

    @staticmethod
    def _get_user(config):
        # overwritten by read-write and admin interface
        user = config.get('data_storage', 'postgres_ro_user')
        password = config.get('data_storage', 'postgres_ro_pw')
        return user, password

    def create_tables(self):
        self.base.metadata.create_all(self.engine)

    @contextmanager
    def get_read_only_session(self) -> Session:
        if self.ro_session is not None:
            yield self.ro_session
        else:
            self.ro_session: Session = self._session_maker()
            try:
                yield self.ro_session
            finally:
                self.ro_session.invalidate()
                self.ro_session = None


class ReadWriteDbInterface(ReadOnlyDbInterface):

    @staticmethod
    def _get_user(config):
        user = config.get('data_storage', 'postgres_rw_user')
        password = config.get('data_storage', 'postgres_rw_pw')
        return user, password

    @contextmanager
    def get_read_write_session(self) -> Session:
        session = self._session_maker()
        try:
            yield session
            session.commit()
        except (SQLAlchemyError, DbInterfaceError) as err:
            logging.error(f'Database error when trying to write to the Database: {err}', exc_info=True)
            session.rollback()
            raise
        finally:
            session.invalidate()

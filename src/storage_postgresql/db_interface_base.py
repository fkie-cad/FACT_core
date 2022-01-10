import logging
from configparser import ConfigParser
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from storage_postgresql.schema import Base


class DbInterfaceError(Exception):
    pass


class ReadOnlyDbInterface:
    def __init__(self, config: ConfigParser):
        self.base = Base
        address = config.get('data_storage', 'postgres_server')
        port = config.get('data_storage', 'postgres_port')
        database = config.get('data_storage', 'postgres_database')
        user = config.get('data_storage', 'postgres_user')
        password = config.get('data_storage', 'postgres_password')
        engine_url = f'postgresql://{user}:{password}@{address}:{port}/{database}'
        self.engine = create_engine(engine_url, pool_size=100, max_overflow=10, pool_recycle=60, future=True)
        self._session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support

    def create_tables(self):
        self.base.metadata.create_all(self.engine)

    @contextmanager
    def get_read_only_session(self) -> Session:
        session: Session = self._session_maker()
        try:
            session.connection(execution_options={'postgresql_readonly': True, 'postgresql_deferrable': True})
            yield session
        finally:
            session.close()


class ReadWriteDbInterface(ReadOnlyDbInterface):

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
            session.close()

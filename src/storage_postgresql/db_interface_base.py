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
        address = config.get('data_storage', 'postgres_server')
        port = config.get('data_storage', 'postgres_port')
        database = config.get('data_storage', 'postgres_database')
        user = config.get('data_storage', 'postgres_user')
        password = config.get('data_storage', 'postgres_password')
        self.engine = create_engine(f'postgresql://{user}:{password}@{address}:{port}/{database}')
        self.base = Base
        self.base.metadata.create_all(self.engine)
        self._session_maker = sessionmaker(bind=self.engine, future=True)  # future=True => sqlalchemy 2.0 support

    @contextmanager
    def get_read_only_session(self) -> Session:
        session: Session = self._session_maker()
        session.connection(execution_options={'postgresql_readonly': True, 'postgresql_deferrable': True})
        try:
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

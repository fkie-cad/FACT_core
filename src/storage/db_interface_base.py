import logging
from contextlib import contextmanager
from typing import Optional

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from storage.db_connection import DbConnection, ReadOnlyConnection, ReadWriteConnection


class DbInterfaceError(Exception):
    pass


class DbSerializationError(DbInterfaceError):
    pass


class ReadOnlyDbInterface:
    def __init__(self, config, connection: Optional[DbConnection] = None):
        self.connection = connection or ReadOnlyConnection(config)
        self.ro_session = None

    @contextmanager
    def get_read_only_session(self) -> Session:
        if self.ro_session is not None:
            yield self.ro_session
            return
        self.ro_session: Session = self.connection.session_maker()
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
    def __init__(self, config, connection: Optional[DbConnection] = None):
        super().__init__(config, connection=connection or ReadWriteConnection(config))

    @contextmanager
    def get_read_write_session(self) -> Session:
        session = self.connection.session_maker()
        try:
            yield session
            session.commit()
        except (SQLAlchemyError, DbInterfaceError) as err:
            session.rollback()
            if 'not JSON serializable' in str(err):
                raise DbSerializationError() from err
            message = 'Database error when trying to write to the database'
            logging.exception(f'{message}: {err}')
            raise DbInterfaceError(message) from err
        finally:
            session.invalidate()

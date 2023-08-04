from __future__ import annotations

import logging
from contextlib import contextmanager

from sqlalchemy.exc import SQLAlchemyError

from storage.db_connection import DbConnection, ReadOnlyConnection, ReadWriteConnection
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


class DbInterfaceError(Exception):
    pass


class DbSerializationError(DbInterfaceError):
    pass


class ReadOnlyDbInterface:
    def __init__(self, connection: DbConnection | None = None):
        self.connection = connection or ReadOnlyConnection()
        self.ro_session: Session | None = None

    @contextmanager
    def get_read_only_session(self) -> Session:
        if self.ro_session is not None:
            yield self.ro_session
            return
        self.ro_session = self.connection.session_maker()
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
    def __init__(self, connection: DbConnection | None = None):
        super().__init__(connection=connection or ReadWriteConnection())

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

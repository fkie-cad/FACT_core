from __future__ import annotations

from sqlalchemy import inspect, text

import config
from storage.db_connection import AdminConnection, DbConnection
from storage.db_interface_base import ReadWriteDbInterface


class Privileges:
    SELECT = 'SELECT'
    INSERT = 'INSERT'
    UPDATE = 'UPDATE'
    DELETE = 'DELETE'
    ALL = 'ALL'


class DbSetup(ReadWriteDbInterface):
    def __init__(self, connection: DbConnection | None = None, **kwargs):
        super().__init__(connection=connection or AdminConnection(**kwargs))

    def create_user(self, user_name: str, password: str):
        if not self.user_exists(user_name):
            with self.get_read_write_session() as session:
                session.execute(
                    text(
                        f"CREATE ROLE {user_name} LOGIN PASSWORD '{password}' NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE;"  # noqa: E501
                    )
                )

    def user_exists(self, user_name: str) -> bool:
        with self.get_read_only_session() as session:
            return bool(
                session.execute(text(f"SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '{user_name}'")).scalar()
            )

    def table_exists(self, table_name: str):
        with self.connection.engine.connect() as db, db.engine.begin() as connection:
            return inspect(connection).has_table(table_name, None)

    def database_exists(self, db_name: str) -> bool:
        with self.get_read_only_session() as session:
            return bool(session.execute(text(f"SELECT 1 FROM pg_database WHERE datname = '{db_name}'")).scalar())

    def create_database(self, db_name: str):
        if not self.database_exists(db_name):
            with self.get_read_write_session() as session:
                session.execute(text(f'CREATE DATABASE {db_name};'))

    def grant_connect(self, database_name: str, user_name: str):
        with self.get_read_write_session() as session:
            session.execute(text(f'GRANT CONNECT ON DATABASE {database_name} TO {user_name};'))

    def grant_usage(self, user_name: str):
        with self.get_read_write_session() as session:
            session.execute(text(f'GRANT USAGE ON SCHEMA public TO {user_name};'))

    def set_table_privileges(self):
        for key, privileges in [
            ('ro', [Privileges.SELECT]),
            ('rw', [Privileges.SELECT, Privileges.INSERT, Privileges.UPDATE]),
            ('del', [Privileges.ALL]),
        ]:
            user = getattr(config.backend.postgres, f'{key}_user')
            for privilege in privileges:
                self.grant_privilege(user, privilege)

    def grant_privilege(self, user_name: str, privilege: str):
        with self.get_read_write_session() as session:
            session.execute(text(f'GRANT {privilege} ON ALL TABLES IN SCHEMA public TO {user_name};'))

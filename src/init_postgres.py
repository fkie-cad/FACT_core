#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
from shlex import split
from subprocess import CalledProcessError, check_output

import config
from helperFunctions.program_setup import setup_logging
from storage.db_setup import DbSetup
from storage.migration import alembic_table_exists, create_alembic_table, set_alembic_revision


def execute_psql_command(
    psql_command: str,
    host,
    port=5432,
    user=os.getenv('PGUSER', default='postgres'),  # noqa: B008
) -> bytes:
    # This is only used to create the fact_admin user.
    # In order to create this user we have to have access to the default admin user (postgres).
    # By default this user does not have a password and "Peer authentication" is used to login to this user.
    # When the database is at a remote server we cant use peer authentication and want to use password authentication.
    # As a workaround to detect which authentication method to use we check the hostname.
    # See https://www.postgresql.org/docs/current/auth-methods.html

    if host in ['localhost', '127.0.0.1']:
        shell_cmd = f'sudo runuser -u {user} -- psql -c "{psql_command}"'
    else:
        shell_cmd = f'psql --host={host} --port={port} --username={user} -c "{psql_command}"'

    try:
        return check_output(split(shell_cmd))
    except CalledProcessError as error:
        logging.error(f'Error during PostgreSQL installation:\n{error.stderr}')
        raise


def user_exists(user_name: str, host: str, port: str | int) -> bool:
    return user_name.encode() in execute_psql_command('\\du', host, port)


def create_admin_user(user_name: str, password: str, host: str, port: int | str):
    execute_psql_command(
        # fmt: off
        (f"CREATE USER {user_name} WITH PASSWORD '{password}' " 'LOGIN SUPERUSER INHERIT CREATEDB CREATEROLE;'),
        # fmt: on
        host=host,
        port=port,
    )


def main(command_line_options=None, config_path: str | None = None, skip_user_creation: bool = False):
    if command_line_options and command_line_options[-1] == '-t':
        return 0  # testing mode

    config.load(config_path)
    setup_logging(None, 'init_postgres')

    host = config.common.postgres.server
    port = config.common.postgres.port

    fact_db = config.common.postgres.database
    test_db = config.common.postgres.test_database

    admin_user = config.common.postgres.admin_user
    admin_password = config.common.postgres.admin_pw

    # skip_user_creation can be helpful if the DB is not directly accessible (e.g. FACT_docker)
    if not skip_user_creation and not user_exists(admin_user, host, port):
        create_admin_user(admin_user, admin_password, host, port)
    db_setup = DbSetup(db_name='postgres', isolation_level='AUTOCOMMIT')
    for db_name in [fact_db, test_db]:
        if not db_setup.database_exists(db_name):
            logging.info(f'Creating table {db_name} ...')
            db_setup.create_database(db_name)
        else:
            logging.info(f'Skipping creation of database {db_name}: already exists')
    _init_users(db_setup, [fact_db, test_db])

    db_setup = DbSetup(db_name=fact_db)
    if not alembic_table_exists():
        logging.info('Creating alembic table...')
        create_alembic_table()
    if not db_setup.table_exists('file_object'):
        logging.info('Creating FACT tables...')
        db_setup.connection.create_tables()
        db_setup.set_table_privileges()
        set_alembic_revision()
    else:
        logging.info('Skipping creation of FACT tables: already exist')

    return 0


def _init_users(db: DbSetup, db_list: list[str]):
    for key in ['ro', 'rw', 'del']:
        user = getattr(config.common.postgres, f'{key}_user')
        pw = getattr(config.common.postgres, f'{key}_pw')

        db.create_user(user, pw)
        for db_name in db_list:
            db.grant_connect(db_name, user)
            # connect to individual databases:
            DbSetup(db_name=db_name).grant_usage(user)


if __name__ == '__main__':
    main()

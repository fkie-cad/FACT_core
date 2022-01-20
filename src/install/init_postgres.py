import logging
from configparser import ConfigParser
from pathlib import Path
from subprocess import check_output
from typing import Optional

try:
    from helperFunctions.config import load_config
except ImportError:
    import sys
    src_dir = Path(__file__).parent.parent
    sys.path.append(str(src_dir))
    from helperFunctions.config import load_config


class Privileges:
    SELECT = 'SELECT'
    INSERT = 'INSERT'
    UPDATE = 'UPDATE'
    DELETE = 'DELETE'
    ALL = 'ALL'


def execute_psql_command(psql_command: str, database: Optional[str] = None):
    database_option = f'-d {database}' if database else ''
    shell_cmd = f'sudo -u postgres psql {database_option} -c "{psql_command}"'
    return check_output(shell_cmd, shell=True)


def user_exists(user_name: str) -> bool:
    return user_name.encode() in execute_psql_command('\\du')


def create_user(user_name: str, password: str):
    execute_psql_command(
        f'CREATE USER {user_name} WITH PASSWORD \'{password}\' '
        'LOGIN NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE;'
    )


def database_exists(database_name: str) -> bool:
    return database_name.encode() in execute_psql_command('\\l')


def create_database(database_name: str):
    execute_psql_command(f'CREATE DATABASE {database_name};')


def grant_privileges(database_name: str, user_name: str, privilege: str):
    execute_psql_command(
        f'GRANT {privilege} ON ALL TABLES IN SCHEMA public TO {user_name};',
        database=database_name
    )


def grant_connect(database_name: str, user_name: str):
    execute_psql_command(f'GRANT CONNECT ON DATABASE {database_name} TO {user_name};')


def grant_usage(database_name: str, user_name: str):
    execute_psql_command(f'GRANT USAGE ON SCHEMA public TO {user_name};', database=database_name)


def change_db_owner(database_name: str, owner: str):
    execute_psql_command(f'ALTER DATABASE {database_name} OWNER TO {owner};')


def main(config: ConfigParser):
    fact_db = config['data_storage']['postgres_database']
    test_db = config['data_storage']['postgres_test_database']

    for key, privileges in [
        ('ro', [Privileges.SELECT]),
        ('rw', [Privileges.SELECT, Privileges.INSERT, Privileges.UPDATE]),
        ('admin', [Privileges.ALL])
    ]:
        user = config['data_storage'][f'postgres_{key}_user']
        pw = config['data_storage'][f'postgres_{key}_pw']
        _create_fact_user(user, pw, [fact_db, test_db], privileges)

    change_db_owner(fact_db, user)
    change_db_owner(test_db, user)


def _create_fact_user(user, pw, databases, privileges):
    logging.info(f'creating user {user}')
    if not user_exists(user):
        create_user(user, pw)
    for db in databases:
        grant_connect(db, user)
        grant_usage(db, user)
        for privilege in privileges:
            grant_privileges(db, user, privilege)


if __name__ == '__main__':
    main(load_config('main.cfg'))

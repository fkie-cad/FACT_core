import logging
from configparser import ConfigParser
from shlex import split
from subprocess import CalledProcessError, check_output
from typing import List, Optional

from helperFunctions.config import load_config
from storage.db_administration import DbAdministration


def execute_psql_command(psql_command: str) -> bytes:
    shell_cmd = f'sudo runuser -u postgres -- psql -c "{psql_command}"'
    try:
        return check_output(split(shell_cmd))
    except CalledProcessError as error:
        logging.error(f'Error during PostgreSQL installation:\n{error.stderr}')
        raise


def user_exists(user_name: str) -> bool:
    return user_name.encode() in execute_psql_command('\\du')


def create_admin_user(user_name: str, password: str):
    execute_psql_command(
        f'CREATE USER {user_name} WITH PASSWORD \'{password}\' '
        'LOGIN SUPERUSER INHERIT CREATEDB CREATEROLE;'
    )


def main(config: Optional[ConfigParser] = None, skip_user_creation: bool = False):
    if config is None:
        logging.info('No custom configuration path provided for PostgreSQL setup. Using main.cfg ...')
        config = load_config('main.cfg')
    fact_db = config['data_storage']['postgres_database']
    test_db = config['data_storage']['postgres_test_database']

    admin_user = config.get('data_storage', 'postgres_admin_user')
    admin_password = config.get('data_storage', 'postgres_admin_pw')

    # skip_user_creation can be helpful if the DB is not directly accessible (e.g. FACT_docker)
    if not skip_user_creation and not user_exists(admin_user):
        create_admin_user(admin_user, admin_password)

    db = DbAdministration(config, db_name='postgres', isolation_level='AUTOCOMMIT')
    for db_name in [fact_db, test_db]:
        db.create_database(db_name)
    _init_users(db, config, [fact_db, test_db])

    db = DbAdministration(config, db_name=fact_db)
    db.create_tables()
    db.set_table_privileges()


def _init_users(db: DbAdministration, config, db_list: List[str]):
    for key in ['ro', 'rw', 'del']:
        user = config['data_storage'][f'postgres_{key}_user']
        pw = config['data_storage'][f'postgres_{key}_pw']
        db.create_user(user, pw)
        for db_name in db_list:
            db.grant_connect(db_name, user)
            # connect to individual databases:
            DbAdministration(config, db_name=db_name).grant_usage(user)


if __name__ == '__main__':
    main()

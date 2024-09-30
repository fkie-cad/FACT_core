import logging
from pathlib import Path

from alembic import command, config, script
from alembic.runtime import migration
from sqlalchemy import inspect

from helperFunctions.fileSystem import get_src_dir
from helperFunctions.install import OperateInDirectory
from storage.db_connection import AdminConnection

ALEMBIC_CFG_PATH = Path(__file__).parent.parent.parent / 'alembic.ini'
ALEMBIC_CFG = config.Config(ALEMBIC_CFG_PATH)


def alembic_table_exists():
    with AdminConnection().engine.connect() as db, db.engine.begin() as connection:
        return inspect(connection).has_table('alembic_version', None)


def get_current_revision():
    # alembic must be executed from src for paths to line up
    with OperateInDirectory(get_src_dir()), AdminConnection().engine.connect().engine.begin() as connection:
        logging.getLogger('alembic.runtime.migration').setLevel(logging.WARNING)  # hide alembic log messages
        context = migration.MigrationContext.configure(connection)
        return context.get_current_revision()


def _get_current_head():
    return script.ScriptDirectory.from_config(ALEMBIC_CFG).get_current_head()


def db_needs_migration():
    current_revision = get_current_revision()
    current_head = _get_current_head()
    logging.info(f'Alembic DB revision:  head: {current_head}, current: {current_revision}')
    return current_revision != current_head


def create_alembic_table():
    command.ensure_version(ALEMBIC_CFG)


def set_alembic_revision(revision='head'):
    # set alembic revision to current head (else alembic thinks the DB needs migration after installation)
    command.stamp(ALEMBIC_CFG, revision)

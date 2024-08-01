import logging
from pathlib import Path

from alembic import command, config, script
from alembic.runtime import migration
from sqlalchemy import inspect

from fact.helperFunctions.fileSystem import get_src_dir
from fact.helperFunctions.install import OperateInDirectory
from fact.storage.db_connection import AdminConnection

ALEMBIC_CFG_PATH = Path(__file__).parent.parent.parent / 'alembic.ini'
ALEMBIC_CFG = config.Config(ALEMBIC_CFG_PATH)


def alembic_table_exists():
    with AdminConnection().engine.connect() as db, db.engine.begin() as connection:
        return inspect(connection).has_table('alembic_version', None)


def db_needs_migration():
    # alembic must be executed from src for paths to line up
    with OperateInDirectory(get_src_dir()), AdminConnection().engine.connect().engine.begin() as connection:
        logging.getLogger('alembic.runtime.migration').setLevel(logging.WARNING)  # hide alembic log messages
        context = migration.MigrationContext.configure(connection)
        current_revision = context.get_current_revision()
        current_head = script.ScriptDirectory.from_config(ALEMBIC_CFG).get_current_head()
        logging.info(f'Alembic DB revision:  head: {current_head}, current: {current_revision}')
        return current_revision != current_head


def create_alembic_table():
    command.ensure_version(ALEMBIC_CFG)


def set_alembic_revision(revision='head'):
    # set alembic revision to current head (else alembic thinks the DB needs migration after installation)
    command.stamp(ALEMBIC_CFG, revision)

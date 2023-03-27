from pathlib import Path

from alembic import config, script
from alembic.runtime import migration

from storage.db_connection import AdminConnection

alembic_cfg_path = Path(__file__).parent.parent.parent / 'alembic.ini'


def db_needs_migration():
    with AdminConnection().engine.connect() as db:
        alembic_cfg = config.Config(alembic_cfg_path)
        script_ = script.ScriptDirectory.from_config(alembic_cfg)
        with db.engine.begin() as connection:
            context = migration.MigrationContext.configure(connection)
            return context.get_current_revision() != script_.get_current_head()

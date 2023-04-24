from pathlib import Path

from alembic import config, script
from alembic.runtime import migration

from helperFunctions.fileSystem import get_src_dir
from helperFunctions.install import OperateInDirectory
from storage.db_connection import AdminConnection


def db_needs_migration():
    return False
    with OperateInDirectory(get_src_dir()):  # alembic must be executed from src for paths to line up
        with AdminConnection().engine.connect() as db:
            alembic_cfg_path = Path(__file__).parent.parent.parent / 'alembic.ini'
            alembic_cfg = config.Config(alembic_cfg_path)
            script_ = script.ScriptDirectory.from_config(alembic_cfg)
            with db.engine.begin() as connection:
                context = migration.MigrationContext.configure(connection)
                return context.get_current_revision() != script_.get_current_head()

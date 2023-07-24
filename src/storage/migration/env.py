from logging.config import fileConfig

from alembic import context

from config import load
from storage.db_connection import AdminConnection
from storage.schema import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

load()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode: create an Engine and associate a connection with the context.
    """
    with AdminConnection().engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=Base.metadata,
        )

        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()

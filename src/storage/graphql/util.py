from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from shlex import split

import config

HASURA_DIR = Path(__file__).parent / 'hasura'


def _db_is_local() -> bool:
    return config.common.postgres.server in ('localhost', '127.0.0.1', '::1', '/var/run/postgresql')


def get_db_url(database: str, user: str, password: str) -> str:
    """The URL under which Hasura (running in a container) reaches `database` on the configured postgres server."""
    if _db_is_local():
        # local postgres => connect through UNIX domain socket (faster than TCP)
        return f'postgresql://{user}:{password}@/{database}?host=/var/run/postgresql'
    return f'postgresql://{user}:{password}@{config.common.postgres.server}:{config.common.postgres.port}/{database}'


def get_env() -> dict[str, str]:
    postgres = config.common.postgres
    return {
        **os.environ,
        'HASURA_ADMIN_SECRET': config.frontend.hasura.admin_secret,
        'FACT_DB_URL': get_db_url(postgres.database, postgres.rw_user, postgres.rw_pw),
        'HASURA_PORT': str(config.frontend.hasura.port),
        'DB_LOCALITY': 'local' if _db_is_local() else 'remote',
    }


def update_hasura_containers() -> None:
    """
    Hasura gets the DB connection (and its port and admin secret) from the environment of its containers, which is
    set when they are created. Bring existing containers in line with the current configuration: `docker compose up`
    recreates only the containers whose configuration changed. Does nothing if Hasura is not set up (no containers).
    """
    try:
        if not _run_compose('ps --all --quiet').strip():
            logging.debug('No Hasura containers found: skipping update')
            return
        _run_compose('up --detach')
    except (OSError, subprocess.CalledProcessError) as error:
        output = getattr(error, 'stdout', None) or error
        logging.warning(f'Could not update the Hasura containers (GraphQL may use an outdated config): {output}')


def _run_compose(arguments: str) -> str:
    return subprocess.run(  # noqa: S603
        split(f'docker compose {arguments}'),
        cwd=HASURA_DIR,
        env=get_env(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    ).stdout

from __future__ import annotations

import os

import config


def get_env() -> dict[str, str]:
    user = config.common.postgres.rw_user
    pw = config.common.postgres.rw_pw
    port = config.common.postgres.port
    server = config.common.postgres.server
    if server in ('localhost', '127.0.0.1', '::1', '/var/run/postgresql'):
        # local postgres => connect through UNIX domain socket (faster than TCP)
        db_url = f'postgresql://{user}:{pw}@/fact_db?host=/var/run/postgresql'
        locality = 'local'
    else:
        db_url = f'postgresql://{user}:{pw}@{server}:{port}/fact_db'
        locality = 'remote'
    return {
        **os.environ,
        'HASURA_ADMIN_SECRET': config.frontend.hasura.admin_secret,
        'FACT_DB_URL': db_url,
        'HASURA_PORT': str(config.frontend.hasura.port),
        'DB_LOCALITY': locality,
    }

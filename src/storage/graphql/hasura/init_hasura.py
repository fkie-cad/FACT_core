from __future__ import annotations

import logging
import sys
from pathlib import Path

import requests
from requests import Response
from requests.adapters import HTTPAdapter, Retry

try:
    import config
except ImportError:
    SRC_DIR = Path(__file__).absolute().parent.parent.parent.parent
    sys.path.append(str(SRC_DIR))
    import config

HTML_OK = 200
HTML_BAD_REQUEST = 400
TRACKED_TABLES = ('analysis', 'file_object', 'firmware', 'fw_files', 'included_files', 'virtual_file_path')
RELATIONSHIPS = {
    'pg_create_object_relationship': [
        # table, name, constraint
        ('analysis', 'file_object', 'uid'),
        ('firmware', 'file_object', 'uid'),
        ('fw_files', 'firmware', 'root_uid'),
        ('fw_files', 'file_object', 'file_uid'),
        ('included_files', 'parent', 'parent_uid'),
        ('included_files', 'child', 'child_uid'),
        ('file_object', 'firmware', 'uid', 'firmware'),
    ],
    'pg_create_array_relationship': [
        ('file_object', 'analysis', 'uid', 'analysis'),
        ('file_object', 'includedFiles', 'root_uid', 'fw_files'),
        ('file_object', 'parentFirmwares', 'file_uid', 'fw_files'),
        ('file_object', 'children', 'parent_uid', 'included_files'),
        ('file_object', 'parents', 'child_uid', 'included_files'),
        ('file_object', 'childrenFilePaths', 'parent_uid', 'virtual_file_path'),
        ('file_object', 'filePaths', 'file_uid', 'virtual_file_path'),
    ],
}


class HasuraInitError(Exception):
    pass


class HasuraSetup:
    def __init__(self, db_name: str | None = None, testing: bool = False):
        self.db_name = db_name or config.common.postgres.database
        self.url = f'http://localhost:{config.frontend.hasura.port}/v1/metadata'
        self.headers = {
            'Content-Type': 'application/json',
            'X-Hasura-Role': 'admin',
            'X-Hasura-Admin-Secret': config.frontend.hasura.admin_secret,
        }
        self.testing = testing

    def init_hasura(self, db_args: dict | None = None):
        logging.info('Waiting for Hasura...')
        self._wait_for_hasura()
        logging.info('Initializing Hasura...')
        if not self._db_was_already_added():
            self._add_database(db_args)
        self._track_tables()
        self._add_relationships()
        self._add_ro_user_role_to_tables()
        logging.info('Hasura initialization successful')

    def _wait_for_hasura(self):
        # Hasura is not ready for connections directly after starting the container, so we may need to wait a bit
        # hasura will return code 200 OK or 500 ERROR on this health check endpoint
        healthcheck_url = self.url.replace('/v1/metadata', '/healthz')
        session = requests.Session()
        # retry 5 times with a total of 30 seconds
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        try:
            session.get(healthcheck_url)
        except (ConnectionRefusedError, ConnectionResetError) as _error:
            raise HasuraInitError('Could not reach Hasura') from _error

    def _add_database(self, additional_args: dict | None = None):
        query = {
            'type': 'pg_add_source',
            'args': {
                'name': self.db_name,
                'configuration': {
                    'connection_info': {
                        'database_url': self._get_db_url(),
                        'pool_settings': {'retries': 1, 'idle_timeout': 180, 'max_connections': 50},
                    },
                },
                **(additional_args or {}),
            },
        }
        response = requests.post(self.url, headers=self.headers, json=query)
        if response.status_code != HTML_OK:
            raise HasuraInitError(f'Failed to add database: {response.json().get("error")}')

    def _get_db_url(self):
        if not self.testing:
            return {'from_env': 'FACT_DB_URL'}
        user = config.common.postgres.ro_user
        pw = config.common.postgres.ro_pw
        return f'postgresql://{user}:{pw}@/fact_test?host=/var/run/postgresql'

    def drop_database(self):
        query = {
            'type': 'pg_drop_source',
            'args': {
                'name': self.db_name,
                'cascade': True,
            },
        }
        response = requests.post(self.url, headers=self.headers, json=query)
        if response.status_code != HTML_OK:
            raise HasuraInitError(f'Failed to drop database: {response.json().get("error")}')

    def _track_tables(self):
        for table in TRACKED_TABLES:
            query = {
                'type': 'pg_track_table',
                'args': {
                    'source': self.db_name,
                    'table': table,
                },
            }
            if self.testing:
                # we need to use another name during testing to avoid naming conflicts
                query['args']['configuration'] = {'custom_name': self._prefix(table)}
            response = requests.post(self.url, headers=self.headers, json=query)
            if response.status_code != HTML_OK:
                if _was_already_added(response):
                    continue
                raise HasuraInitError(f'Failed to track table {table}: {response.json().get("error")}')

    def _add_relationships(self):
        for action, relation_list in RELATIONSHIPS.items():
            for table, name, *constraints in relation_list:
                if len(constraints) == 1:
                    constraint = constraints[0]
                else:
                    column, other_table = constraints
                    constraint = {
                        'column': column,
                        'table': {'name': other_table, 'schema': 'public'},
                    }
                query = {
                    'type': action,
                    'args': {
                        'table': table,
                        'name': self._prefix(name),
                        'source': self.db_name,
                        'using': {'foreign_key_constraint_on': constraint},
                    },
                }
                response = requests.post(self.url, headers=self.headers, json=query)
                if response.status_code != HTML_OK:
                    if _was_already_added(response):
                        continue
                    raise HasuraInitError(
                        f'Failed to add constraint {name} on table {table}: {response.json().get("error")}'
                    )

    def _db_was_already_added(self) -> bool:
        query = {'type': 'pg_get_source_tables', 'args': {'source': self.db_name}}
        response = requests.post(self.url, headers=self.headers, json=query)
        if response.status_code not in {HTML_OK, HTML_BAD_REQUEST}:
            raise HasuraInitError('No connection to Hasura API. Is it running?')
        data = response.json()
        return not (isinstance(data, dict) and 'error' in data)

    def _add_ro_user_role_to_tables(self):
        for table in TRACKED_TABLES:
            query = {
                'type': 'pg_create_select_permission',
                'args': {
                    'source': self.db_name,
                    'table': table,
                    'role': 'ro_user',
                    'permission': {'columns': '*', 'filter': {}, 'allow_aggregations': True},
                },
            }
            response = requests.post(self.url, headers=self.headers, json=query)
            if response.status_code != HTML_OK:
                if _was_already_added(response):
                    continue
                raise HasuraInitError(f'Failed to role to table {table}: {response.json().get("error")}')

    def _prefix(self, attribute: str) -> str:
        return f'test_{attribute}' if self.testing else attribute


def _was_already_added(response: Response) -> bool:
    data = response.json()
    return isinstance(data, dict) and 'error' in data and data.get('code') in ('already-exists', 'already-tracked')


if __name__ == '__main__':
    config.load()
    try:
        HasuraSetup().init_hasura()
    except HasuraInitError as error:
        logging.exception(f'Error during Hasura init: {error}')
        sys.exit(1)
    sys.exit(0)

from __future__ import annotations

import logging
import sys
from pathlib import Path

import docker
import requests
from requests import Response
from requests.adapters import HTTPAdapter, Retry

try:
    import config
except ImportError:
    SRC_DIR = Path(__file__).parent.parent.parent.parent
    sys.path.append(str(SRC_DIR))
    import config

config.load()
HTML_OK = 200
HTML_BAD_REQUEST = 400
DB_NAME = 'fact_db'
URL = f'http://localhost:{config.frontend.hasura.port}/v1/metadata'
HEADERS = {
    'Content-Type': 'application/json',
    'X-Hasura-Role': 'admin',
    'X-Hasura-Admin-Secret': config.frontend.hasura.admin_secret,
}
client = docker.from_env()

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
        ('file_object', 'firmware', {'column': 'uid', 'table': {'name': 'firmware', 'schema': 'public'}}),
    ],
    'pg_create_array_relationship': [
        ('file_object', 'analysis', {'column': 'uid', 'table': {'name': 'analysis', 'schema': 'public'}}),
        (
            'file_object',
            'firmwareFilesByFirmware',
            {'column': 'root_uid', 'table': {'name': 'fw_files', 'schema': 'public'}},
        ),
        (
            'file_object',
            'firmwareFilesByFile',
            {'column': 'file_uid', 'table': {'name': 'fw_files', 'schema': 'public'}},
        ),
        (
            'file_object',
            'includedFilesByParent',
            {'column': 'parent_uid', 'table': {'name': 'included_files', 'schema': 'public'}},
        ),
        (
            'file_object',
            'includedFilesByChild',
            {'column': 'child_uid', 'table': {'name': 'included_files', 'schema': 'public'}},
        ),
        (
            'file_object',
            'FilePathsByParent',
            {'column': 'parent_uid', 'table': {'name': 'virtual_file_path', 'schema': 'public'}},
        ),
        (
            'file_object',
            'FilePathsByFile',
            {'column': 'file_uid', 'table': {'name': 'virtual_file_path', 'schema': 'public'}},
        ),
    ],
}


def init_hasura():
    logging.info('Waiting for Hasura...')
    _wait_for_hasura()
    logging.info('Initializing Hasura...')
    if not _db_was_already_added():
        _add_database()
    _track_tables()
    _add_relationships()
    _add_ro_user_role_to_tables()
    logging.info('Hasura initialization successful')


def _wait_for_hasura():
    # Hasura is not ready for connections directly after starting the container so we may need to wait a bit
    # hasura will return code 200 OK or 500 ERROR on this health check endpoint
    healthcheck_url = f'http://localhost:{config.frontend.hasura.port}/healthz'
    session = requests.Session()
    # retry 5 times with a total of 30 seconds
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[500])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    try:
        session.get(healthcheck_url)
    except (ConnectionRefusedError, ConnectionResetError):
        logging.exception('Could not reach Hasura')
        sys.exit(1)


def _add_database():
    query = {
        'type': 'pg_add_source',
        'args': {
            'name': DB_NAME,
            'configuration': {
                'connection_info': {
                    'database_url': {'from_env': 'FACT_DB_URL'},
                    'pool_settings': {'retries': 1, 'idle_timeout': 180, 'max_connections': 50},
                },
            },
        },
    }
    response = requests.post(URL, headers=HEADERS, json=query)
    if response.status_code != HTML_OK:
        logging.error(f'Failed to add database: {response.text}')
        sys.exit(5)


def _track_tables():
    for table in TRACKED_TABLES:
        query = {
            'type': 'pg_track_table',
            'args': {
                'source': DB_NAME,
                'table': table,
            },
        }
        response = requests.post(URL, headers=HEADERS, json=query)
        if response.status_code != HTML_OK:
            if _was_already_added(response):
                continue
            logging.error(f'Failed to track table {table}: {response.text}')
            sys.exit(6)


def _add_relationships():
    for action, relation_list in RELATIONSHIPS.items():
        for table, name, constraint in relation_list:
            query = {
                'type': action,
                'args': {
                    'table': table,
                    'name': name,
                    'source': DB_NAME,
                    'using': {'foreign_key_constraint_on': constraint},
                },
            }
            response = requests.post(URL, headers=HEADERS, json=query)
            if response.status_code != HTML_OK:
                if _was_already_added(response):
                    continue
                logging.error(f'Failed to add constraint {name} on table {table}: {response.text}')
                sys.exit(7)


def _was_already_added(response: Response) -> bool:
    data = response.json()
    return isinstance(data, dict) and 'error' in data and data.get('code') in ('already-exists', 'already-tracked')


def _db_was_already_added() -> bool:
    query = {'type': 'pg_get_source_tables', 'args': {'source': DB_NAME}}
    response = requests.post(URL, headers=HEADERS, json=query)
    if response.status_code not in {HTML_OK, HTML_BAD_REQUEST}:
        logging.error('No connection to Hasura API. Is it running?')
        sys.exit(4)
    data = response.json()
    if isinstance(data, dict) and 'error' in data:
        return False
    return True


def _add_ro_user_role_to_tables():
    for table in TRACKED_TABLES:
        query = {
            'type': 'pg_create_select_permission',
            'args': {
                'source': DB_NAME,
                'table': table,
                'role': 'ro_user',
                'permission': {'columns': '*', 'filter': {}},
            },
        }
        response = requests.post(URL, headers=HEADERS, json=query)
        if response.status_code != HTML_OK:
            if _was_already_added(response):
                continue
            logging.error(f'Failed to role to table {table}: {response.text}')
            sys.exit(8)


if __name__ == '__main__':
    init_hasura()
    sys.exit(0)

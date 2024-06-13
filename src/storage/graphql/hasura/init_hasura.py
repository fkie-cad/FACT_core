from __future__ import annotations

import logging
import sys
from pathlib import Path

import docker
import requests
from requests import Response

try:
    import config
except ImportError:
    SRC_DIR = Path(__file__).parent.parent.parent
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
        ('fw_files', 'fileObjectByRootUid', 'root_uid'),
        ('fw_files', 'fileObjectByFileUid', 'file_uid'),
        ('fw_files', 'file_object', 'root_uid'),
        ('included_files', 'fileObjectByParentUid', 'parent_uid'),
        ('included_files', 'file_object', 'child_uid'),
        ('file_object', 'firmware', {'column': 'uid', 'table': {'name': 'firmware', 'schema': 'public'}}),
    ],
    'pg_create_array_relationship': [
        ('file_object', 'analyses', {'column': 'uid', 'table': {'name': 'analysis', 'schema': 'public'}}),
        ('file_object', 'fwFilesByRootUid', {'column': 'root_uid', 'table': {'name': 'fw_files', 'schema': 'public'}}),
        ('file_object', 'fw_files', {'column': 'file_uid', 'table': {'name': 'fw_files', 'schema': 'public'}}),
        (
            'file_object',
            'includedFilesByParentUid',
            {'column': 'parent_uid', 'table': {'name': 'included_files', 'schema': 'public'}},
        ),
        (
            'file_object',
            'included_files',
            {'column': 'child_uid', 'table': {'name': 'included_files', 'schema': 'public'}},
        ),
        (
            'file_object',
            'virtualFilePathsByParentUid',
            {'column': 'parent_uid', 'table': {'name': 'virtual_file_path', 'schema': 'public'}},
        ),
        (
            'file_object',
            'virtual_file_paths',
            {'column': 'file_uid', 'table': {'name': 'virtual_file_path', 'schema': 'public'}},
        ),
    ],
}


def init_hasura():
    logging.info('Initializing Hasura...')
    if not _db_was_already_added():
        _add_database()
    _track_tables()
    _add_relationships()
    logging.info('Hasura initialization successful')


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


if __name__ == '__main__':
    init_hasura()
    sys.exit(0)

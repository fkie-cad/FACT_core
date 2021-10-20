import json
import logging
import sys
from base64 import b64encode

from sqlalchemy.exc import StatementError

from helperFunctions.config import load_config
from helperFunctions.database import ConnectTo
from storage.db_interface_compare import CompareDbInterface
from storage_postgresql.db_interface import DbInterface

try:
    from tqdm import tqdm
except ImportError:
    print('Error: tqdm not found. Please install it:\npython3 -m pip install tqdm')
    sys.exit(1)


def _fix_illegal_dict(dict_: dict, label=''):
    for key, value in dict_.items():
        if isinstance(value, bytes):
            if key == 'entropy_analysis_graph':
                logging.debug('converting to base64...')
                dict_[key] = b64encode(value).decode()
            elif key == 'strace':
                logging.debug('converting strace to base64...')
                dict_[key] = b64encode(value).decode()
            elif label == 'users_and_passwords':
                logging.debug('converting users_and_passwords entry to str...')
                dict_[key] = value.decode(errors='replace').replace('\0', '\\x00')
            else:
                logging.debug(f'entry ({label}) {key} has illegal type bytes: {value[:10]}')
                sys.exit(1)
        elif isinstance(value, dict):
            _fix_illegal_dict(value, label)
        elif isinstance(value, list):
            _fix_illegal_list(value, key, label)
        elif isinstance(value, str):
            if '\0' in value:
                logging.debug(f'entry ({label}) {key} contains illegal character "\\0": {value[:10]} -> replacing with "?"')
                dict_[key] = value.replace('\0', '\\x00')


def _fix_illegal_list(list_: list, key=None, label=''):
    for i, element in enumerate(list_):
        if isinstance(element, bytes):
            logging.debug(f'array entry ({label}) {key} has illegal type bytes: {element[:10]}... -> converting to str...')
            list_[i] = element.decode()
        elif isinstance(element, dict):
            _fix_illegal_dict(element, label)
        elif isinstance(element, list):
            _fix_illegal_list(element, key, label)
        elif isinstance(element, str):
            if '\0' in element:
                logging.debug(f'entry ({label}) {key} contains illegal character "\\0": {element[:10]} -> replacing with "?"')
                list_[i] = element.replace('\0', '\\x00')


def _check_for_missing_fields(plugin, analysis_data):
    required_fields = ['plugin_version', 'analysis_date']
    for field in required_fields:
        if field not in analysis_data:
            logging.debug(f'{plugin} result is missing {field}')
            analysis_data[field] = '0'


def main():
    postgres = DbInterface()
    config = load_config('main.cfg')

    with ConnectTo(CompareDbInterface, config) as db:
        migrate(postgres, {}, db, True)


def migrate(postgres, query, db, root=False, root_uid=None, parent_uid=None):
    label = 'firmware' if root else 'file_object'
    collection = db.firmwares if root else db.file_objects
    total = collection.count_documents(query)
    logging.debug(f'Migrating {total} {label} entries')
    for entry in tqdm(collection.find(query, {'_id': 1}), total=total, leave=root):
        uid = entry['_id']
        if postgres.exists(uid):
            if not root:
                postgres.update_file_object_parents(uid, root_uid, parent_uid)
            # root fw uid must be updated for all included files :(
            firmware_object = db.get_object(uid)
            query = {'_id': {'$in': list(firmware_object.files_included)}}
            migrate(postgres, query, db, root_uid=firmware_object.uid if root else root_uid, parent_uid=firmware_object.uid)
        else:
            firmware_object = (db.get_firmware if root else db.get_file_object)(uid)
            firmware_object.parents = [parent_uid]
            firmware_object.parent_firmware_uids = [root_uid]
            for plugin, plugin_data in firmware_object.processed_analysis.items():
                _fix_illegal_dict(plugin_data, plugin)
                _check_for_missing_fields(plugin, plugin_data)
            try:
                (postgres.insert_firmware if root else postgres.insert_file_object)(firmware_object)
            except StatementError:
                logging.error(f'Firmware contains errors: {firmware_object}')
                raise
            except KeyError:
                logging.error(
                    f'fields missing from analysis data: \n'
                    f'{json.dumps(firmware_object.processed_analysis, indent=2)}',
                    exc_info=True
                )
                raise
            query = {'_id': {'$in': list(firmware_object.files_included)}}
            root_uid = firmware_object.uid if root else root_uid
            migrate(postgres, query, db, root_uid=root_uid, parent_uid=firmware_object.uid)


if __name__ == '__main__':
    main()

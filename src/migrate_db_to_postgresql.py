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
                print('converting to base64...')
                dict_[key] = b64encode(value).decode()
            elif key == 'strace':
                print('converting strace to base64...')
                dict_[key] = b64encode(value).decode()
            elif label == 'users_and_passwords':
                print('converting users_and_passwords entry to str...')
                dict_[key] = value.decode(errors='replace').replace('\0', '\\x00')
            else:
                print(f'entry ({label}) {key} has illegal type bytes: {value[:10]}')
                sys.exit(1)
        elif isinstance(value, dict):
            _fix_illegal_dict(value, label)
        elif isinstance(value, list):
            _fix_illegal_list(value, key, label)
        elif isinstance(value, str):
            if '\0' in value:
                print(f'entry ({label}) {key} contains illegal character "\\0": {value[:10]} -> replacing with "?"')
                dict_[key] = value.replace('\0', '\\x00')


def _fix_illegal_list(list_: list, key=None, label=''):
    for i, element in enumerate(list_):
        if isinstance(element, bytes):
            print(f'array entry ({label}) {key} has illegal type bytes: {element[:10]}... -> converting to str...')
            list_[i] = element.decode()
        elif isinstance(element, dict):
            _fix_illegal_dict(element, label)
        elif isinstance(element, list):
            _fix_illegal_list(element, key, label)
        elif isinstance(element, str):
            if '\0' in element:
                print(f'entry ({label}) {key} contains illegal character "\\0": {element[:10]} -> replacing with "?"')
                list_[i] = element.replace('\0', '\\x00')


def _check_for_missing_fields(plugin, analysis_data):
    required_fields = ['plugin_version', 'analysis_date']
    for field in required_fields:
        if field not in analysis_data:
            print(f'{plugin} result is missing {field}')
            analysis_data[field] = '0'


def main():
    postgres = DbInterface()
    config = load_config('main.cfg')

    with ConnectTo(CompareDbInterface, config) as db:
        for label, collection, insert_function in [
            ('firmware', db.firmwares, postgres.insert_firmware),
            ('file_object', db.file_objects, postgres.insert_file_object),
        ]:
            total = collection.count_documents({})
            print(f'Migrating {total} {label} entries')
            for entry in tqdm(collection.find({}, {'_id': 1}), total=total):
                uid = entry['_id']
                if not postgres.file_object_exists(uid):
                    firmware_object = db.get_object(uid)
                    for plugin, plugin_data in firmware_object.processed_analysis.items():
                        _fix_illegal_dict(plugin_data, plugin)
                        _check_for_missing_fields(plugin, plugin_data)
                    try:
                        insert_function(firmware_object)
                    except StatementError:
                        print(f'Firmware contains errors: {firmware_object}')
                        raise
                    except KeyError:
                        logging.error('fields missing from analysis data:', exc_info=True)
                        print(json.dumps(firmware_object.processed_analysis, indent=2))
                        raise


if __name__ == '__main__':
    main()

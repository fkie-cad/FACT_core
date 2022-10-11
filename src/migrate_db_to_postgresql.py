import json
import logging
import pickle
import sys
from base64 import b64encode
from typing import List, Optional, Union

import gridfs
from pymongo import MongoClient, errors
from sqlalchemy.exc import StatementError

from helperFunctions.config import load_config
from helperFunctions.data_conversion import convert_time_to_str
from helperFunctions.database import ConnectTo
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_backend import BackendDbInterface
from storage.db_interface_comparison import ComparisonDbInterface

try:
    from rich.progress import BarColumn, Progress, TimeElapsedColumn
except ImportError:
    print('Error: rich not found. Please install it:\npython3 -m pip install rich')
    sys.exit(1)

PERCENTAGE = '[progress.percentage]{task.percentage:>3.0f}%'
DESCRIPTION = '[progress.description]{task.description}'


class MongoInterface:
    '''
    This is the mongo interface base class handling:
    - load config
    - setup connection including authentication
    '''

    READ_ONLY = False

    def __init__(self, config=None):
        self.config = config
        mongo_server = self.config['data-storage']['mongo-server']
        mongo_port = self.config['data-storage']['mongo-port']
        self.client = MongoClient(f'mongodb://{mongo_server}:{mongo_port}', connect=False)
        self._authenticate()
        self._setup_database_mapping()

    def shutdown(self):
        self.client.close()

    def _setup_database_mapping(self):
        pass

    def _authenticate(self):
        if self.READ_ONLY:
            user, pw = self.config['data-storage']['db-readonly-user'], self.config['data-storage']['db-readonly-pw']
        else:
            user, pw = self.config['data-storage']['db-admin-user'], self.config['data-storage']['db-admin-pw']
        try:
            self.client.admin.authenticate(user, pw, mechanism='SCRAM-SHA-1')
        except errors.OperationFailure as error:  # Authentication not successful
            logging.error(f'Error: Authentication not successful: {error}')
            sys.exit(1)


class MigrationMongoInterface(MongoInterface):
    def _setup_database_mapping(self):
        main_database = self.config['data-storage']['main-database']
        self.main = self.client[main_database]
        self.firmwares = self.main.firmwares
        self.file_objects = self.main.file_objects
        self.compare_results = self.main.compare_results
        # sanitize stuff
        sanitize_db = self.config['data-storage'].get('sanitize-database', 'faf_sanitize')
        self.sanitize_storage = self.client[sanitize_db]
        self.sanitize_fs = gridfs.GridFS(self.sanitize_storage)

    def get_object(self, uid, analysis_filter=None):
        """
        input uid
        output:
            - firmware_object if uid found in firmware database
            - else: file_object if uid found in file_database
            - else: None
        """
        fo = self.get_file_object(uid, analysis_filter=analysis_filter)
        if fo is None:
            fo = self.get_firmware(uid, analysis_filter=analysis_filter)
        return fo

    def get_firmware(self, uid: str, analysis_filter: Optional[List[str]] = None) -> Optional[Firmware]:
        firmware_entry = self.firmwares.find_one(uid)
        if firmware_entry:
            return self._convert_to_firmware(firmware_entry, analysis_filter=analysis_filter)
        logging.debug(f'No firmware with UID {uid} found.')
        return None

    def _convert_to_firmware(self, entry: dict, analysis_filter: List[str] = None) -> Firmware:
        firmware = Firmware()
        firmware.uid = entry['_id']
        firmware.size = entry['size']
        firmware.sha256 = entry['sha256']
        firmware.file_name = entry['file_name']
        firmware.device_name = entry['device_name']
        firmware.device_class = entry['device_class']
        firmware.release_date = convert_time_to_str(entry['release_date'])
        firmware.vendor = entry['vendor']
        firmware.version = entry['version']
        firmware.processed_analysis = self.retrieve_analysis(
            entry['processed_analysis'], analysis_filter=analysis_filter
        )
        firmware.files_included = set(entry['files_included'])
        firmware.virtual_file_path = entry['virtual_file_path']
        firmware.tags = entry.get('tags', {})
        firmware.set_part_name(entry.get('device_part', 'complete'))
        firmware.comments = entry.get('comments', [])
        return firmware

    def get_file_object(self, uid: str, analysis_filter: Optional[List[str]] = None) -> Optional[FileObject]:
        file_entry = self.file_objects.find_one(uid)
        if file_entry:
            return self._convert_to_file_object(file_entry, analysis_filter=analysis_filter)
        logging.debug(f'No FileObject with UID {uid} found.')
        return None

    def _convert_to_file_object(self, entry: dict, analysis_filter: Optional[List[str]] = None) -> FileObject:
        file_object = FileObject()
        file_object.uid = entry['_id']
        file_object.size = entry['size']
        file_object.sha256 = entry['sha256']
        file_object.file_name = entry['file_name']
        file_object.virtual_file_path = entry['virtual_file_path']
        file_object.parents = entry['parents']
        file_object.processed_analysis = self.retrieve_analysis(
            entry['processed_analysis'], analysis_filter=analysis_filter
        )
        file_object.files_included = set(entry['files_included'])
        file_object.parent_firmware_uids = set(entry['parent_firmware_uids'])
        file_object.comments = entry.get('comments', [])
        return file_object

    def retrieve_analysis(self, sanitized_dict: dict, analysis_filter: Optional[List[str]] = None) -> dict:
        """
        retrieves analysis including sanitized entries
        :param sanitized_dict: processed analysis dictionary including references to sanitized entries
        :param analysis_filter: list of analysis plugins to be restored
        :default None:
        :return: dict
        """
        if analysis_filter is None:
            plugins = sanitized_dict.keys()
        else:
            # only use the plugins from analysis_filter that are actually in the results
            plugins = set(sanitized_dict.keys()).intersection(analysis_filter)
        for key in plugins:
            try:
                if sanitized_dict[key]['file_system_flag']:
                    logging.debug(f'Retrieving stored file {key}')
                    sanitized_dict[key].pop('file_system_flag')
                    sanitized_dict[key] = self._retrieve_binaries(sanitized_dict, key)
                else:
                    sanitized_dict[key].pop('file_system_flag')
            except (KeyError, IndexError, AttributeError, TypeError, pickle.PickleError, gridfs.errors.NoFile):
                logging.exception(f'Could not retrieve sanitized analysis:\n{sanitized_dict.get(key, {})}')
        return sanitized_dict

    def _retrieve_binaries(self, sanitized_dict, key):
        tmp_dict = {}
        for analysis_key in sanitized_dict[key].keys():
            if self.is_not_sanitized(analysis_key, sanitized_dict[key]):
                tmp_dict[analysis_key] = sanitized_dict[key][analysis_key]
            else:
                logging.debug(f'Retrieving {analysis_key}')
                tmp = self.sanitize_fs.get_last_version(sanitized_dict[key][analysis_key])
                if tmp is not None:
                    report = pickle.loads(tmp.read())
                else:
                    logging.error(f'sanitized file not found: {sanitized_dict[key][analysis_key]}')
                    report = {}
                tmp_dict[analysis_key] = report
        return tmp_dict

    @staticmethod
    def is_not_sanitized(field, analysis_result):
        # As of now, all _saved_ fields are dictionaries, so the str check ensures it's not a reference to gridFS
        return field in ['summary', 'tags'] and not isinstance(analysis_result[field], str)


def _fix_illegal_dict(dict_: dict, label=''):  # pylint: disable=too-complex
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
                logging.debug(
                    f'entry ({label}) {key} contains illegal character "\\0": {value[:10]} -> replacing with "?"'
                )
                dict_[key] = value.replace('\0', '\\x00')


def _fix_illegal_list(list_: list, key=None, label=''):
    for index, element in enumerate(list_):
        if isinstance(element, bytes):
            logging.debug(
                f'array entry ({label}) {key} has illegal type bytes: {element[:10]}... -> converting to str...'
            )
            list_[index] = element.decode()
        elif isinstance(element, dict):
            _fix_illegal_dict(element, label)
        elif isinstance(element, list):
            _fix_illegal_list(element, key, label)
        elif isinstance(element, str):
            if '\0' in element:
                logging.debug(
                    f'entry ({label}) {key} contains illegal character "\\0": {element[:10]} -> replacing with "?"'
                )
                list_[index] = element.replace('\0', '\\x00')


def _migrate_plugin(plugin_name, processed_analysis):
    if plugin_name == 'cpu_architecture':
        architectures = {}
        for key in list(processed_analysis):
            if key not in ['analysis_date', 'plugin_version', 'skipped', 'summary', 'system_version', 'tags']:
                architectures[key] = processed_analysis.pop(key)

        processed_analysis['architectures'] = architectures


def _check_for_missing_fields(plugin, analysis_data):
    required_fields = ['plugin_version', 'analysis_date']
    for field in required_fields:
        if field not in analysis_data:
            logging.debug(f'{plugin} result is missing {field}')
            analysis_data[field] = '0'


def main():
    postgres_config = load_config('main.cfg')
    postgres = BackendDbInterface(config=postgres_config)

    mongo_config = load_config('migration.cfg')
    try:
        with ConnectTo(MigrationMongoInterface, mongo_config) as db:
            with Progress(DESCRIPTION, BarColumn(), PERCENTAGE, TimeElapsedColumn()) as progress:
                migrator = DbMigrator(postgres=postgres, mongo=db, progress=progress)
                migrated_fw_count = migrator.migrate_fw(query={}, root=True, label='firmwares')
                if not migrated_fw_count:
                    print('No firmware to migrate')
                else:
                    print(f'Successfully migrated {migrated_fw_count} firmware DB entries')
            migrate_comparisons(db, postgres_config)
    except errors.ServerSelectionTimeoutError:
        logging.error(
            'Could not connect to MongoDB database.\n\t'
            'Is the server running and the configuration in `src/config/migration.cfg` correct?\n\t'
            'The database can be started with `mongod --config config/mongod.conf`.'
        )
        sys.exit(1)


class DbMigrator:
    def __init__(self, postgres: BackendDbInterface, mongo: MigrationMongoInterface, progress: Progress):
        self.postgres = postgres
        self.mongo = mongo
        self.progress = progress

    def migrate_fw(self, query, label: str = None, root=False, root_uid=None, parent_uid=None) -> int:
        migrated_fw_count = 0
        collection = self.mongo.firmwares if root else self.mongo.file_objects
        total = collection.count_documents(query)
        if not total:
            return 0
        task = self.progress.add_task(f'[{"green" if root else "cyan"}]{label}', total=total)
        for entry in collection.find(query, {'_id': 1}):
            uid = entry['_id']
            if self.postgres.exists(uid):
                if not root:
                    self.postgres.update_file_object_parents(uid, root_uid, parent_uid)
                # root fw uid must be updated for all included files :(
                firmware_object = self.mongo.get_object(uid)
                query = {'_id': {'$in': list(firmware_object.files_included)}}
                self.migrate_fw(
                    query,
                    label=firmware_object.file_name,
                    root_uid=firmware_object.uid if root else root_uid,
                    parent_uid=firmware_object.uid,
                )
            else:
                firmware_object = self.mongo.get_object(uid)
                self._migrate_single_object(firmware_object, parent_uid, root_uid)
                query = {'_id': {'$in': list(firmware_object.files_included)}}
                root_uid = firmware_object.uid if root else root_uid
                self.migrate_fw(
                    query=query, root_uid=root_uid, parent_uid=firmware_object.uid, label=firmware_object.file_name
                )
                migrated_fw_count += 1
            self.progress.update(task, advance=1)
        self.progress.remove_task(task)
        return migrated_fw_count

    def _migrate_single_object(self, firmware_object: Union[Firmware, FileObject], parent_uid: str, root_uid: str):
        firmware_object.parents = [parent_uid]
        firmware_object.parent_firmware_uids = [root_uid]
        for plugin, plugin_data in firmware_object.processed_analysis.items():
            _fix_illegal_dict(plugin_data, plugin)
            _check_for_missing_fields(plugin, plugin_data)
            _migrate_plugin(plugin, plugin_data)
        try:
            self.postgres.insert_object(firmware_object)
        except StatementError:
            logging.error(f'Firmware contains errors: {firmware_object}')
            raise
        except KeyError:
            logging.error(
                f'fields missing from analysis data: \n' f'{json.dumps(firmware_object.processed_analysis, indent=2)}',
                exc_info=True,
            )
            raise


def migrate_comparisons(mongo: MigrationMongoInterface, config):
    count = 0
    compare_db = ComparisonDbInterface(config=config)
    for entry in mongo.compare_results.find({}):
        results = {key: value for key, value in entry.items() if key not in ['_id', 'submission_date']}
        comparison_id = entry['_id']
        if not compare_db.comparison_exists(comparison_id):
            if not compare_db.all_uids_found_in_database(comparison_id.split(';')):
                logging.warning(f'Could not migrate comparison {comparison_id}: not all firmwares found in the DB')
                continue
            compare_db.insert_comparison(comparison_id, results)
            count += 1
    if not count:
        print('No firmware comparison entries to migrate')
    else:
        print(f'Migrated {count} comparison DB entries')


if __name__ == '__main__':
    main()

# pylint: disable=no-self-use,unused-argument
import os
from base64 import standard_b64encode
from configparser import ConfigParser
from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Optional, Union

from helperFunctions.config import load_config
from helperFunctions.data_conversion import get_value_of_first_key
from helperFunctions.fileSystem import get_src_dir
from intercom.common_mongo_binding import InterComMongoInterface
from objects.file import FileObject
from objects.firmware import Firmware
from storage.mongo_interface import MongoInterface
from storage_postgresql.db_interface_common import DbInterfaceCommon


def get_test_data_dir():
    '''
    Returns the absolute path of the test data directory
    '''
    return os.path.join(get_src_dir(), 'test/data')


class CommonDbInterfaceMock(DbInterfaceCommon):

    def __init__(self):  # pylint: disable=super-init-not-called
        class Collection:
            def aggregate(self, *_, **__):
                return []

        self.file_objects = Collection()

    def retrieve_analysis(self, sanitized_dict, analysis_filter=None):
        return {}


def create_test_firmware(device_class='Router', device_name='test_router', vendor='test_vendor', bin_path='container/test.zip', all_files_included_set=False, version='0.1'):
    fw = Firmware(file_path=os.path.join(get_test_data_dir(), bin_path))
    fw.device_class = device_class
    fw.device_name = device_name
    fw.vendor = vendor

    fw.release_date = '1970-01-01'
    fw.version = version
    processed_analysis = {
        'dummy': {'summary': ['sum a', 'fw exclusive sum a'], 'content': 'abcd', 'plugin_version': '0', 'analysis_date': '0'},
        'unpacker': {'plugin_used': 'used_unpack_plugin', 'plugin_version': '1.0', 'analysis_date': '0'},
        'file_type': {'mime': 'test_type', 'full': 'Not a PE file', 'summary': ['a summary'], 'plugin_version': '1.0', 'analysis_date': '0'}
    }

    fw.processed_analysis.update(processed_analysis)
    if all_files_included_set:
        fw.list_of_all_included_files = list(fw.files_included)
        fw.list_of_all_included_files.append(fw.uid)
    return fw


def create_test_file_object(bin_path='get_files_test/testfile1'):
    fo = FileObject(file_path=os.path.join(get_test_data_dir(), bin_path))
    processed_analysis = {
        'dummy': {'summary': ['sum a', 'file exclusive sum b'], 'content': 'file abcd', 'plugin_version': '0', 'analysis_date': '0'},
        'file_type': {'full': 'Not a PE file', 'plugin_version': '1.0', 'analysis_date': '0'},
        'unpacker': {'file_system_flag': False, 'plugin_used': 'unpacker_name', 'plugin_version': '1.0', 'analysis_date': '0'}
    }
    fo.processed_analysis.update(processed_analysis)
    fo.virtual_file_path = fo.get_virtual_file_paths()
    return fo


TEST_FW = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
TEST_FW_2 = create_test_firmware(device_class='test_class', device_name='test_firmware_2', vendor='test vendor', bin_path='container/test.7z')
TEST_TEXT_FILE = create_test_file_object()
TEST_TEXT_FILE2 = create_test_file_object(bin_path='get_files_test/testfile2')
NICE_LIST_DATA = {
    'uid': TEST_FW.uid,
    'files_included': TEST_FW.files_included,
    'size': TEST_FW.size,
    'mime-type': 'file-type-plugin/not-run-yet',
    'current_virtual_path': get_value_of_first_key(TEST_FW.get_virtual_file_paths())
}

TEST_SEARCH_QUERY = {'_id': '0000000000000000000000000000000000000000000000000000000000000000_1', 'search_query': f'{{"_id": "{TEST_FW_2.uid}"}}', 'query_title': 'rule a_ascii_string_rule'}


class MockFileObject:

    def __init__(self, binary=b'test string', file_path='/bin/ls'):
        self.binary = binary
        self.file_path = file_path
        self.processed_analysis = {'file_type': {'mime': 'application/x-executable'}}


class CommonIntercomMock:
    tasks = []

    def __init__(self, *_, **__):
        pass

    @staticmethod
    def get_available_analysis_plugins():
        common_fields = ('0.0.', [], [], [], 1)
        return {
            'default_plugin': ('default plugin description', False, {'default': True}, *common_fields),
            'mandatory_plugin': ('mandatory plugin description', True, {'default': False}, *common_fields),
            'optional_plugin': ('optional plugin description', False, {'default': False}, *common_fields),
            'file_type': ('file_type plugin', False, {'default': False}, *common_fields),
            'unpacker': ('Additional information provided by the unpacker', True, False)
        }

    def shutdown(self):
        pass

    def peek_in_binary(self, *_):
        return b'foobar'


class CommonDatabaseMock:  # pylint: disable=too-many-public-methods
    fw_uid = TEST_FW.uid
    fo_uid = TEST_TEXT_FILE.uid
    fw2_uid = TEST_FW_2.uid

    def __init__(self, config=None):
        self.tasks = []
        self.locks = []

    def update_view(self, file_name, content):
        pass

    def get_object(self, uid, analysis_filter=None):
        if uid == TEST_FW.uid:
            result = deepcopy(TEST_FW)
            result.processed_analysis = {
                'file_type': {'mime': 'application/octet-stream', 'full': 'test text'},
                'mandatory_plugin': 'mandatory result',
                'optional_plugin': 'optional result'
            }
            return result
        if uid == TEST_TEXT_FILE.uid:
            result = deepcopy(TEST_TEXT_FILE)
            result.processed_analysis = {
                'file_type': {'mime': 'text/plain', 'full': 'plain text'}
            }
            return result
        if uid == self.fw2_uid:
            result = deepcopy(TEST_FW_2)
            result.processed_analysis = {
                'file_type': {'mime': 'filesystem/cramfs', 'full': 'test text'},
                'mandatory_plugin': 'mandatory result',
                'optional_plugin': 'optional result'
            }
            result.release_date = '2000-01-01'
            return result
        return None

    def get_hid(self, uid, root_uid=None):
        return 'TEST_FW_HID'

    def get_device_class_list(self):
        return ['test class']

    def page_compare_results(self):
        return []

    def get_vendor_list(self):
        return ['test vendor']

    def get_device_name_dict(self):
        return {'test class': {'test vendor': ['test device']}}

    def get_number_of_total_matches(self, *_, **__):
        return 10

    # ToDo
    # def compare_result_is_in_db(self, uid_list):
    #     return uid_list == normalize_compare_id(';'.join([TEST_FW.uid, TEST_TEXT_FILE.uid]))
    #
    # def check_objects_exist(self, compare_id):
    #     if compare_id == normalize_compare_id(';'.join([TEST_FW_2.uid, TEST_FW.uid])):
    #         return None
    #     if compare_id == normalize_compare_id(';'.join([TEST_TEXT_FILE.uid, TEST_FW.uid])):
    #         return None
    #     raise FactComparisonException('bla')

    def exists(self, uid):
        return uid in (self.fw_uid, self.fo_uid, self.fw2_uid, 'error')

    def all_uids_found_in_database(self, uid_list):
        return True

    def get_data_for_nice_list(self, input_data, root_uid):
        return [NICE_LIST_DATA]

    @staticmethod
    def page_comparison_results():
        return []

    @staticmethod
    def create_analysis_structure():
        return ''

    # def add_binary_search_request(self, yara_rule_binary, firmware_uid=None):
    #     if yara_rule_binary == b'invalid_rule':
    #         return 'error: invalid rule'
    #     return 'some_id'
    #
    # def get_complete_object_including_all_summaries(self, uid):
    #     if uid == TEST_FW.uid:
    #         return TEST_FW
    #     raise Exception('UID not found: {}'.format(uid))
    #
    # def rest_get_firmware_uids(self, offset, limit, query=None, recursive=False, inverted=False):
    #     if (offset != 0) or (limit != 0):
    #         return []
    #     return [TEST_FW.uid, ]
    #
    # def rest_get_file_object_uids(self, offset, limit, query=None):
    #     if (offset != 0) or (limit != 0):
    #         return []
    #     return [TEST_TEXT_FILE.uid, ]
    #
    # def search_cve_summaries_for(self, keyword):
    #     return [{'_id': 'CVE-2012-0002'}]
    #
    # def get_all_ssdeep_hashes(self):
    #     return [
    #         {'_id': '3', 'processed_analysis': {'file_hashes': {
    #             'ssdeep': '384:aztrofSbs/7qkBYbplFPEW5d8aODW9EyGqgm/nZuxpIdQ1s4JtUn:Urofgs/uK2lF8W5dxWyGS/AxpIws'}}},
    #         {'_id': '4', 'processed_analysis': {'file_hashes': {
    #             'ssdeep': '384:aztrofSbs/7qkBYbplFPEW5d8aODW9EyGqgm/nZuxpIdQ1s4JwT:Urofgs/uK2lF8W5dxWyGS/AxpIwA'}}}
    #     ]

    def get_other_versions_of_firmware(self, fo):
        return []

    def is_firmware(self, uid):
        return uid == 'uid_in_db'

    def get_file_name(self, uid):
        if uid == 'deadbeef00000000000000000000000000000000000000000000000000000000_123':
            return 'test_name'
        return None

    def set_unpacking_lock(self, uid):
        self.locks.append(uid)

    def check_unpacking_lock(self, uid):
        return uid in self.locks

    # def get_file_name(self, uid):
    #     if uid == 'deadbeef00000000000000000000000000000000000000000000000000000000_123':
    #         return 'test_name'
    #     return None

    def get_summary(self, fo, selected_analysis):
        if fo.uid == TEST_FW.uid and selected_analysis == 'foobar':
            return {'foobar': ['some_uid']}
        return None
    #
    # def find_missing_files(self):
    #     return {'parent_uid': ['missing_child_uid']}
    #
    # def find_missing_analyses(self):
    #     return {'root_fw_uid': ['missing_child_uid']}
    #
    # def find_failed_analyses(self):
    #     return {'plugin': ['missing_child_uid']}
    #
    # def find_orphaned_objects(self):
    #     return {'root_fw_uid': ['missing_child_uid']}


def fake_exit(self, *args):
    pass


def get_database_names(config):
    prefix = config.get('data_storage', 'intercom_database_prefix')
    databases = [f'{prefix}_{intercom_db}' for intercom_db in InterComMongoInterface.INTERCOM_CONNECTION_TYPES]
    databases.extend([
        config.get('data_storage', 'main_database'),
        config.get('data_storage', 'view_storage'),
        config.get('data_storage', 'statistic_database')
    ])
    return databases


# FixMe: still useful for intercom
def clean_test_database(config, list_of_test_databases):
    db = MongoInterface(config=config)
    try:
        for database_name in list_of_test_databases:
            db.client.drop_database(database_name)
    except Exception:  # pylint: disable=broad-except
        pass
    db.shutdown()


def get_firmware_for_rest_upload_test():
    testfile_path = os.path.join(get_test_data_dir(), 'container/test.zip')
    with open(testfile_path, 'rb') as fp:
        file_content = fp.read()
    data = {
        'binary': standard_b64encode(file_content).decode(),
        'file_name': 'test.zip',
        'device_name': 'test_device',
        'device_part': 'test_part',
        'device_class': 'test_class',
        'version': '1.0',
        'vendor': 'test_vendor',
        'release_date': '1970-01-01',
        'tags': '',
        'requested_analysis_systems': ['software_components']
    }
    return data


def get_config_for_testing(temp_dir: Optional[Union[TemporaryDirectory, str]] = None):
    if isinstance(temp_dir, TemporaryDirectory):
        temp_dir = temp_dir.name
    config = ConfigParser()
    config.add_section('data_storage')
    config.set('data_storage', 'mongo_server', 'localhost')
    config.set('data_storage', 'main_database', 'tmp_unit_tests')
    config.set('data_storage', 'intercom_database_prefix', 'tmp_unit_tests')
    config.set('data_storage', 'statistic_database', 'tmp_unit_tests')
    config.set('data_storage', 'view_storage', 'tmp_tests_view')
    config.set('data_storage', 'mongo_port', '27018')
    config.set('data_storage', 'report_threshold', '2048')
    config.set('data_storage', 'password_salt', '1234')
    config.set('data_storage', 'firmware_file_storage_directory', '/tmp/fact_test_fs_directory')
    config.add_section('unpack')
    config.set('unpack', 'whitelist', '')
    config.set('unpack', 'max_depth', '10')
    config.add_section('default_plugins')
    config.add_section('ExpertSettings')
    config.set('ExpertSettings', 'block_delay', '0.1')
    config.set('ExpertSettings', 'ssdeep_ignore', '1')
    config.set('ExpertSettings', 'authentication', 'false')
    config.set('ExpertSettings', 'intercom_poll_delay', '0.5')
    config.set('ExpertSettings', 'nginx', 'false')
    config.add_section('database')
    config.set('database', 'results_per_page', '10')
    load_users_from_main_config(config)
    config.add_section('Logging')
    if temp_dir is not None:
        config.set('data_storage', 'firmware_file_storage_directory', temp_dir)
        config.set('Logging', 'mongoDbLogFile', os.path.join(temp_dir, 'mongo.log'))
    config.set('ExpertSettings', 'radare2_host', 'localhost')
    # -- postgres -- FixMe? --
    config.set('data_storage', 'postgres_server', 'localhost')
    config.set('data_storage', 'postgres_port', '5432')
    config.set('data_storage', 'postgres_database', 'fact_test2')
    return config


def load_users_from_main_config(config: ConfigParser):
    fact_config = load_config('main.cfg')
    config.set('data_storage', 'db_admin_user', fact_config['data_storage']['db_admin_user'])
    config.set('data_storage', 'db_admin_pw', fact_config['data_storage']['db_admin_pw'])
    config.set('data_storage', 'db_readonly_user', fact_config['data_storage']['db_readonly_user'])
    config.set('data_storage', 'db_readonly_pw', fact_config['data_storage']['db_readonly_pw'])
    # -- postgres -- FixMe? --
    config.set('data_storage', 'postgres_user', fact_config.get('data_storage', 'postgres_user'))
    config.set('data_storage', 'postgres_password', fact_config.get('data_storage', 'postgres_password'))


def store_binary_on_file_system(tmp_dir: str, test_object: Union[FileObject, Firmware]):
    binary_dir = Path(tmp_dir) / test_object.uid[:2]
    binary_dir.mkdir(parents=True)
    (binary_dir / test_object.uid).write_bytes(test_object.binary)

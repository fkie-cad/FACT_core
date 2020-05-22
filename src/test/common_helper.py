# pylint: disable=no-self-use,unused-argument
import json
import os
from base64 import standard_b64encode
from configparser import ConfigParser
from copy import deepcopy

from helperFunctions.config import load_config
from helperFunctions.dataConversion import get_value_of_first_key, normalize_compare_id
from helperFunctions.fileSystem import get_src_dir
from intercom.common_mongo_binding import InterComMongoInterface
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_common import MongoInterfaceCommon
from storage.db_interface_compare import FactCompareException
from storage.mongo_interface import MongoInterface


def get_test_data_dir():
    '''
    Returns the absolute path of the test data directory
    '''
    return os.path.join(get_src_dir(), 'test/data')


class CommonDbInterfaceMock(MongoInterfaceCommon):

    def __init__(self):  # pylint: disable=super-init-not-called
        pass

    def retrieve_analysis(self, sanitized_dict, analysis_filter=None):
        return {}


def create_test_firmware(device_class='Router', device_name='test_router', vendor='test_vendor', bin_path='container/test.zip', all_files_included_set=False, version='0.1'):
    fw = Firmware(file_path=os.path.join(get_test_data_dir(), bin_path))
    fw.set_device_class(device_class)
    fw.set_device_name(device_name)
    fw.set_vendor(vendor)

    fw.set_release_date('1970-01-01')
    fw.version = version
    processed_analysis = {
        'dummy': {'summary': ['sum a', 'fw exclusive sum a'], 'content': 'abcd'},
        'unpacker': {'plugin_used': 'used_unpack_plugin'},
        'file_type': {'mime': 'test_type', 'full': 'Not a PE file'}
    }

    fw.processed_analysis.update(processed_analysis)
    if all_files_included_set:
        fw.list_of_all_included_files = list(fw.files_included)
        fw.list_of_all_included_files.append(fw.uid)
    return fw


def create_test_file_object(bin_path='get_files_test/testfile1'):
    fo = FileObject(file_path=os.path.join(get_test_data_dir(), bin_path))
    processed_analysis = {
        'dummy': {'summary': ['sum a', 'file exclusive sum b'], 'content': 'file abcd'},
        'file_type': {'full': 'Not a PE file'},
        'unpacker': {'file_system_flag': False, 'plugin_used': 'unpacker_name'}
    }
    fo.processed_analysis.update(processed_analysis)
    fo.virtual_file_path = fo.get_virtual_file_paths()
    return fo


TEST_FW = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
TEST_FW_2 = create_test_firmware(device_class='test_class', device_name='test_firmware_2', vendor='test vendor', bin_path='container/test.7z')
TEST_TEXT_FILE = create_test_file_object()
NICE_LIST_DATA = {
    'uid': TEST_FW.uid,
    'files_included': TEST_FW.files_included,
    'size': TEST_FW.size,
    'mime-type': 'file-type-plugin/not-run-yet',
    'current_virtual_path': get_value_of_first_key(TEST_FW.get_virtual_file_paths())
}


class MockFileObject:

    def __init__(self, binary=b'test string', file_path='/bin/ls'):
        self.binary = binary
        self.file_path = file_path
        self.processed_analysis = {'file_type': {'mime': 'application/x-executable'}}


class DatabaseMock:  # pylint: disable=too-many-public-methods
    fw_uid = TEST_FW.uid
    fo_uid = TEST_TEXT_FILE.uid
    fw2_uid = TEST_FW_2.uid

    def __init__(self, config=None):
        self.tasks = []
        self.locks = []

    def shutdown(self):
        pass

    def update_view(self, file_name, content):
        pass

    def get_meta_list(self, firmware_list=None):
        fw_entry = ('test_uid', 'test firmware', 'unpacker')
        fo_entry = ('test_fo_uid', 'test file object', 'unpacker')
        if firmware_list and self.fw_uid in firmware_list and self.fo_uid in firmware_list:
            return [fw_entry, fo_entry]
        if firmware_list and self.fo_uid in firmware_list:
            return [fo_entry]
        return [fw_entry]

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
        return list()

    def get_vendor_list(self):
        return ['test vendor']

    def get_device_name_dict(self):
        return {'test class': {'test vendor': ['test device']}}

    def compare_result_is_in_db(self, uid_list):
        return uid_list == normalize_compare_id(';'.join([TEST_FW.uid, TEST_TEXT_FILE.uid]))

    def get_compare_result(self, compare_id):
        if compare_id == normalize_compare_id(';'.join([TEST_FW.uid, TEST_FW_2.uid])):
            return {
                'this_is': 'a_compare_result',
                'general': {'hid': {TEST_FW.uid: 'foo', TEST_TEXT_FILE.uid: 'bar'}},
                'plugins': {'File_Coverage': {'some_feature': {TEST_FW.uid: [TEST_TEXT_FILE.uid]}}}
            }
        if compare_id == normalize_compare_id(';'.join([TEST_FW.uid, TEST_TEXT_FILE.uid])):
            return {'this_is': 'a_compare_result'}
        return 'generic error'

    def existence_quick_check(self, uid):
        return uid in (self.fw_uid, self.fo_uid, self.fw2_uid, 'error')

    def check_objects_exist(self, compare_id):
        if compare_id == normalize_compare_id(';'.join([TEST_FW_2.uid, TEST_FW.uid])):
            return None
        if compare_id == normalize_compare_id(';'.join([TEST_TEXT_FILE.uid, TEST_FW.uid])):
            return None
        raise FactCompareException('bla')

    def all_uids_found_in_database(self, uid_list):
        return True

    def add_comment_to_object(self, uid, comment, author, time):
        TEST_FW.comments.append(
            {'time': str(time), 'author': author, 'comment': comment}
        )

    def add_to_search_query_cache(self, search_query: str, query_title: str = None) -> str:
        return '0000000000000000000000000000000000000000000000000000000000000000_0'

    def get_query_from_cache(self, query_uid):
        return {'search_query': '{{"_id": "{}"}}'.format(format(TEST_FW_2.uid)), 'query_title': 'test'}

    class firmwares:  # pylint: disable=invalid-name
        @staticmethod
        def find_one(uid):
            if uid == 'test_uid':
                return 'test'
            if uid == TEST_FW.uid:
                return TEST_FW.uid
            return None

        @staticmethod
        def find(query, query_filter):
            return {}

    class file_objects:  # pylint: disable=invalid-name
        @staticmethod
        def find_one(uid):
            if uid == TEST_TEXT_FILE.uid:
                return TEST_TEXT_FILE.uid
            return None

        @staticmethod
        def find(query, query_filter):
            return {}

    def get_data_for_nice_list(self, input_data, root_uid):
        return [NICE_LIST_DATA, ]

    @staticmethod
    def create_analysis_structure():
        return ''

    def generic_search(self, search_string, skip=0, limit=0, only_fo_parent_firmware=False, inverted=False):
        result = []
        if isinstance(search_string, dict):
            search_string = json.dumps(search_string)
        if self.fw_uid in search_string or search_string == '{}':
            result.append(self.fw_uid)
        if self.fo_uid in search_string or search_string == '{}':
            if not only_fo_parent_firmware:
                result.append(self.fo_uid)
            else:
                if self.fw_uid not in result:
                    result.append(self.fw_uid)
        return result

    def add_analysis_task(self, task):
        self.tasks.append(task)

    def add_re_analyze_task(self, task, unpack=True):
        self.tasks.append(task)

    def add_single_file_task(self, task):
        self.tasks.append(task)

    def add_compare_task(self, task, force=None):
        self.tasks.append((task, force))

    def get_available_analysis_plugins(self):
        common_fields = ('0.0.', [], [], [], 1)
        return {
            'default_plugin': ('default plugin description', False, {'default': True}, *common_fields),
            'mandatory_plugin': ('mandatory plugin description', True, {'default': False}, *common_fields),
            'optional_plugin': ('optional plugin description', False, {'default': False}, *common_fields),
            'file_type': ('file_type plugin', False, {'default': False}, *common_fields)
        }

    def get_binary_and_filename(self, uid):
        if uid == TEST_FW.uid:
            return TEST_FW.binary, TEST_FW.file_name
        if uid == TEST_TEXT_FILE.uid:
            return TEST_TEXT_FILE.binary, TEST_TEXT_FILE.file_name
        return None

    def get_repacked_binary_and_file_name(self, uid):
        if uid == TEST_FW.uid:
            return TEST_FW.binary, '{}.tar.gz'.format(TEST_FW.file_name)
        return None, None

    def add_binary_search_request(self, yara_rule_binary, firmware_uid=None):
        if yara_rule_binary == b'invalid_rule':
            return 'error: invalid rule'
        return 'some_id'

    def get_binary_search_result(self, uid):
        if uid == 'some_id':
            return {'test_rule': ['test_uid']}, b'some yara rule'
        return None, None

    def get_statistic(self, identifier):
        statistics = {
            'number_of_firmwares': 1,
            'number_of_unique_files': 0,
            'total_firmware_size': 10,
            'total_file_size': 20,
            'average_firmware_size': 10,
            'average_file_size': 20,
            'benchmark': 61
        }
        if identifier == 'general':
            return statistics
        if identifier == 'release_date':
            return {'date_histogram_data': [['July 2014', 1]]}
        return None

    def get_complete_object_including_all_summaries(self, uid):
        if uid == TEST_FW.uid:
            return TEST_FW
        raise Exception('UID not found: {}'.format(uid))

    def rest_get_firmware_uids(self, offset, limit, query=None, recursive=False, inverted=False):
        if (offset != 0) or (limit != 0):
            return []
        return [TEST_FW.uid, ]

    def rest_get_file_object_uids(self, offset, limit, query=None):
        if (offset != 0) or (limit != 0):
            return []
        return [TEST_TEXT_FILE.uid, ]

    def get_firmware(self, uid, analysis_filter=None):
        return self.get_object(uid, analysis_filter)

    def get_file_object(self, uid, analysis_filter=None):
        return self.get_object(uid, analysis_filter)

    def search_cve_summaries_for(self, keyword):
        return [{'_id': 'CVE-2012-0002'}]

    def get_all_ssdeep_hashes(self):
        return [
            {'_id': '3', 'processed_analysis': {'file_hashes': {
                'ssdeep': '384:aztrofSbs/7qkBYbplFPEW5d8aODW9EyGqgm/nZuxpIdQ1s4JtUn:Urofgs/uK2lF8W5dxWyGS/AxpIws'}}},
            {'_id': '4', 'processed_analysis': {'file_hashes': {
                'ssdeep': '384:aztrofSbs/7qkBYbplFPEW5d8aODW9EyGqgm/nZuxpIdQ1s4JwT:Urofgs/uK2lF8W5dxWyGS/AxpIwA'}}}
        ]

    def get_other_versions_of_firmware(self, fo):
        return []

    def get_view(self, name):
        if name == 'plugin_1':
            return b'<plugin 1 view>'
        return None

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

    def drop_unpacking_locks(self):
        self.locks = []

    def get_specific_fields_of_db_entry(self, uid, field_dict):
        return None  # TODO

    def get_summary(self, fo, selected_analysis):
        if fo.uid == TEST_FW.uid and selected_analysis == 'foobar':
            return {'foobar': ['some_uid']}
        return None

    def find_missing_files(self):
        return {'parent_uid': ['missing_child_uid']}

    def find_missing_analyses(self):
        return {'root_fw_uid': ['missing_child_uid']}


def fake_exit(self, *args):
    pass


def get_database_names(config):
    databases = ['{}_{}'.format(config.get('data_storage', 'intercom_database_prefix'), intercom_db)
                 for intercom_db in InterComMongoInterface.INTERCOM_CONNECTION_TYPES]
    databases.extend([config.get('data_storage', 'main_database'), config.get(
        'data_storage', 'view_storage'), config.get('data_storage', 'statistic_database')])
    return databases


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
        'release_date': '01.01.1970',
        'tags': '',
        'requested_analysis_systems': ['software_components']
    }
    return data


def get_config_for_testing(temp_dir=None):
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
        config.set('data_storage', 'firmware_file_storage_directory', temp_dir.name)
        config.set('Logging', 'mongoDbLogFile', os.path.join(temp_dir.name, 'mongo.log'))
    return config


def load_users_from_main_config(config: ConfigParser):
    fact_config = load_config('main.cfg')
    config.set('data_storage', 'db_admin_user', fact_config['data_storage']['db_admin_user'])
    config.set('data_storage', 'db_admin_pw', fact_config['data_storage']['db_admin_pw'])
    config.set('data_storage', 'db_readonly_user', fact_config['data_storage']['db_readonly_user'])
    config.set('data_storage', 'db_readonly_pw', fact_config['data_storage']['db_readonly_pw'])

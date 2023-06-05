from __future__ import annotations

# pylint: disable=no-self-use,unused-argument
import os
from base64 import standard_b64encode
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path

from helperFunctions.data_conversion import get_value_of_first_key
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.tag import TagColor
from objects.file import FileObject
from objects.firmware import Firmware


def get_test_data_dir():
    '''
    Returns the absolute path of the test data directory
    '''
    return os.path.join(get_src_dir(), 'test/data')


def create_test_firmware(
    device_class='Router',
    device_name='test_router',
    vendor='test_vendor',
    bin_path='container/test.zip',
    all_files_included_set=False,
    version='0.1',
):
    fw = Firmware(file_path=os.path.join(get_test_data_dir(), bin_path))
    fw.device_class = device_class
    fw.device_name = device_name
    fw.vendor = vendor
    fw.tags = {'test_tag': TagColor.GRAY}

    fw.release_date = '1970-01-01'
    fw.version = version
    processed_analysis = {
        'dummy': {
            'summary': ['sum a', 'fw exclusive sum a'],
            'result': {
                'content': 'abcd',
            },
            'plugin_version': '0',
            'analysis_date': 0.0,
        },
        'unpacker': {
            'result': {
                'plugin_used': 'used_unpack_plugin',
            },
            'plugin_version': '1.0',
            'analysis_date': 0.0,
        },
        'file_type': {
            'result': {
                'mime': 'test_type',
                'full': 'Not a PE file',
            },
            'summary': ['a summary'],
            'plugin_version': '1.0',
            'analysis_date': 0.0,
        },
    }

    fw.processed_analysis.update(processed_analysis)
    if all_files_included_set:
        fw.list_of_all_included_files = list(fw.files_included)
        fw.list_of_all_included_files.append(fw.uid)
    return fw


def create_test_file_object(bin_path='get_files_test/testfile1', uid=None, analyses=None):
    fo = FileObject(file_path=os.path.join(get_test_data_dir(), bin_path))
    processed_analysis = {
        'dummy': {
            'summary': ['sum a', 'file exclusive sum b'],
            'result': {
                'content': 'file abcd',
            },
            'plugin_version': '0',
            'analysis_date': '0',
        },
        'file_type': {
            'result': {
                'full': 'Not a PE file',
                'mime': 'test_type',
            },
            'plugin_version': '1.0',
            'analysis_date': '0',
        },
        'unpacker': {
            'result': {
                'file_system_flag': False,
                'plugin_used': 'unpacker_name',
            },
            'plugin_version': '1.0',
            'analysis_date': '0',
        },
    }
    if analyses:
        processed_analysis.update(analyses)
    if uid:
        fo.uid = uid
    fo.processed_analysis.update(processed_analysis)
    fo.virtual_file_path = fo.get_virtual_file_paths()
    return fo


TEST_FW = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
TEST_FW_2 = create_test_firmware(
    device_class='test_class', device_name='test_firmware_2', vendor='test vendor', bin_path='container/test.7z'
)
TEST_TEXT_FILE = create_test_file_object()
TEST_TEXT_FILE2 = create_test_file_object(bin_path='get_files_test/testfile2')
NICE_LIST_DATA = {
    'uid': TEST_FW.uid,
    'files_included': TEST_FW.files_included,
    'size': TEST_FW.size,
    'mime-type': 'file-type-plugin/not-run-yet',
    'current_virtual_path': get_value_of_first_key(TEST_FW.get_virtual_file_paths()),
}
COMPARISON_ID = f'{TEST_FW.uid};{TEST_FW_2.uid}'

TEST_SEARCH_QUERY = {
    '_id': '0000000000000000000000000000000000000000000000000000000000000000_1',
    'search_query': f'{{"_id": "{TEST_FW_2.uid}"}}',
    'query_title': 'rule a_ascii_string_rule',
}


class MockFileObject:
    def __init__(self, binary=b'test string', file_path='/bin/ls'):
        self.binary = binary
        self.file_path = file_path
        self.processed_analysis = {'file_type': {'result': {'mime': 'application/x-executable'}}}


class CommonDatabaseMock:  # pylint: disable=too-many-public-methods
    fw_uid = TEST_FW.uid
    fo_uid = TEST_TEXT_FILE.uid
    fw2_uid = TEST_FW_2.uid

    def __init__(self, config=None):
        self.tasks = []
        self.locks = []

    @contextmanager
    def get_read_only_session(self):
        yield None

    def update_view(self, file_name, content):
        pass

    def get_object(self, uid, analysis_filter=None):
        if uid == TEST_FW.uid:
            result = deepcopy(TEST_FW)
            result.processed_analysis = {
                'file_type': {'result': {'mime': 'application/octet-stream', 'full': 'test text'}},
                'mandatory_plugin': {'result': 'mandatory result'},
                'optional_plugin': {'result': 'optional result'},
            }
            return result
        if uid == TEST_TEXT_FILE.uid:
            result = deepcopy(TEST_TEXT_FILE)
            result.processed_analysis = {'file_type': {'result': {'mime': 'text/plain', 'full': 'plain text'}}}
            return result
        if uid == self.fw2_uid:
            result = deepcopy(TEST_FW_2)
            result.processed_analysis = {
                'file_type': {'result': {'mime': 'filesystem/cramfs', 'full': 'test text'}},
                'mandatory_plugin': {'result': 'mandatory result'},
                'optional_plugin': {'result': 'optional result'},
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

    def get_other_versions_of_firmware(self, fo):
        return []

    def is_firmware(self, uid):
        return uid == 'uid_in_db'

    def get_file_name(self, uid):
        if uid == 'deadbeef00000000000000000000000000000000000000000000000000000000_123':
            return 'test_name'
        return None

    def get_summary(self, fo, selected_analysis):
        if fo.uid == TEST_FW.uid and selected_analysis == 'foobar':
            return {'foobar': ['some_uid']}
        return None

    # === Comparison ===

    @staticmethod
    def comparison_exists(comparison_id):
        if comparison_id == COMPARISON_ID:
            return True
        return False

    @staticmethod
    def get_comparison_result(comparison_id):
        if comparison_id == COMPARISON_ID:
            return {
                'general': {'hid': {TEST_FW.uid: 'hid1', TEST_FW_2.uid: 'hid2'}},
                '_id': comparison_id,
                'submission_date': 0.0,
            }
        return None

    @staticmethod
    def objects_exist(compare_id):
        if compare_id in ['existing_id', 'uid1;uid2', COMPARISON_ID]:
            return True
        return False


def fake_exit(self, *args):
    pass


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
        'requested_analysis_systems': ['software_components'],
    }
    return data


def store_binary_on_file_system(tmp_dir: str, test_object: FileObject | Firmware):
    binary_dir = Path(tmp_dir) / test_object.uid[:2]
    binary_dir.mkdir(parents=True)
    (binary_dir / test_object.uid).write_bytes(test_object.binary)


def setup_test_tables(db_setup):
    db_setup.connection.create_tables()
    db_setup.set_table_privileges()


def clear_test_tables(db_setup):
    db_setup.connection.base.metadata.drop_all(db_setup.connection.engine)


def generate_analysis_entry(
    plugin_version: str = '1.0',
    analysis_date: float = 0.0,
    summary: list[str] | None = None,
    tags: dict | None = None,
    analysis_result: dict | None = None,
):
    return {
        'plugin_version': plugin_version,
        'analysis_date': analysis_date,
        'summary': summary or [],
        'tags': tags or {},
        'result': analysis_result or {},
    }

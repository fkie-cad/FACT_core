# pylint:disable=attribute-defined-outside-init,protected-access

import gc
import json
import pickle
from os import path
from tempfile import TemporaryDirectory
from typing import Set

import pytest

from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_backend import BackEndDbInterface
from storage.db_interface_common import MongoInterfaceCommon
from test.common_helper import (
    TestBase, create_test_file_object, create_test_firmware, get_config_for_testing, get_test_data_dir
)

TESTS_DIR = get_test_data_dir()
test_file_one = path.join(TESTS_DIR, 'get_files_test/testfile1')
TMP_DIR = TemporaryDirectory(prefix='fact_test_')


@pytest.mark.usefixtures('use_db')
class TestMongoInterface(TestBase):

    @classmethod
    def setup_class(cls):
        super().setup_class()
        cls.config.set('data_storage', 'report_threshold', '32')
        cls.config.set('data_storage', 'sanitize_database', 'tmp_sanitize')

    def setup(self):
        self.db_interface = MongoInterfaceCommon(config=self.config)
        self.db_interface_backend = BackEndDbInterface(config=self.config)

        self.test_firmware = create_test_firmware()

        self.test_yara_match = {
            'rule': 'OpenSSH',
            'tags': [],
            'namespace': 'default',
            'strings': [(0, '$a', b'OpenSSH')],
            'meta': {
                'description': 'SSH library',
                'website': 'http://www.openssh.com',
                'open_source': True,
                'software_name': 'OpenSSH'
            },
            'matches': True
        }

        self.test_fo = create_test_file_object()

    def teardown(self):
        self.db_interface_backend.client.drop_database(self.config.get('data_storage', 'main_database'))
        self.db_interface_backend.shutdown()
        self.db_interface.client.drop_database(self.config.get('data_storage', 'sanitize_database'))
        self.db_interface.shutdown()
        gc.collect()

    def _get_all_firmware_uids(self):
        uid_list = []
        tmp = self.db_interface.firmwares.find()
        for item in tmp:
            uid_list.append(item['_id'])
        return uid_list

    def test_existence_quick_check(self):
        assert not self.db_interface.existence_quick_check('none_existing'), 'none existing firmware found'
        self.db_interface_backend.add_firmware(self.test_firmware)
        assert self.db_interface.existence_quick_check(self.test_firmware.uid), 'existing firmware not found'
        self.db_interface_backend.add_file_object(self.test_fo)
        assert self.db_interface.existence_quick_check(self.test_fo.uid), 'existing file not found'

    def test_get_firmware(self):
        self.db_interface_backend.add_firmware(self.test_firmware)
        fw_object = self.db_interface.get_firmware(self.test_firmware.uid)
        assert fw_object.vendor == 'test_vendor'
        assert fw_object.device_name == 'test_router'
        assert fw_object.part == ''

    def test_get_object(self):
        fo = self.db_interface.get_object(self.test_firmware.uid)
        assert fo is None, 'found something but there is nothing in the database'
        self.db_interface_backend.add_firmware(self.test_firmware)
        fo = self.db_interface.get_object(self.test_firmware.uid)
        assert isinstance(fo, Firmware), 'firmware has wrong type'
        assert fo.device_name == 'test_router', 'Device name in Firmware not correct'
        test_file = FileObject(file_path=path.join(get_test_data_dir(), 'get_files_test/testfile2'))
        self.db_interface_backend.add_file_object(test_file)
        fo = self.db_interface.get_object(test_file.uid)
        assert isinstance(fo, FileObject), 'file object has wrong type'

    def test_get_complete_object_including_all_summaries(self):
        self.db_interface_backend.report_threshold = 1024
        test_file = create_test_file_object()
        self.test_firmware.add_included_file(test_file)
        self.db_interface_backend.add_firmware(self.test_firmware)
        self.db_interface_backend.add_file_object(test_file)
        tmp = self.db_interface.get_complete_object_including_all_summaries(self.test_firmware.uid)
        assert isinstance(tmp, Firmware), 'wrong type'
        assert 'summary' in tmp.processed_analysis['dummy'].keys(), 'summary not found in processed analysis'
        assert 'sum a' in tmp.processed_analysis['dummy']['summary'], 'summary of original file not included'
        assert 'file exclusive sum b' in tmp.processed_analysis['dummy']['summary'], 'summary of included file not found'

    def test_sanitize_analysis(self):
        short_dict = {'stub_plugin': {'result': 0}}
        long_dict = {'stub_plugin': {'result': 10000000000, 'misc': 'Bananarama', 'summary': []}}

        self.test_firmware.processed_analysis = short_dict
        sanitized_dict = self.db_interface.sanitize_analysis(self.test_firmware.processed_analysis, self.test_firmware.uid)
        assert 'file_system_flag' in sanitized_dict['stub_plugin'].keys()
        assert not sanitized_dict['stub_plugin']['file_system_flag']
        assert self.db_interface.sanitize_fs.list() == [], 'file stored in db but should not'

        self.test_firmware.processed_analysis = long_dict
        sanitized_dict = self.db_interface.sanitize_analysis(self.test_firmware.processed_analysis, self.test_firmware.uid)
        assert 'stub_plugin_result_{}'.format(self.test_firmware.uid) in self.db_interface.sanitize_fs.list(), 'sanitized file not stored'
        assert 'summary_result_{}'.format(self.test_firmware.uid) not in self.db_interface.sanitize_fs.list(), 'summary is erroneously stored'
        assert 'file_system_flag' in sanitized_dict['stub_plugin'].keys()
        assert sanitized_dict['stub_plugin']['file_system_flag']
        assert isinstance(sanitized_dict['stub_plugin']['summary'], list)

    def test_retrieve_analysis(self):
        self.db_interface.sanitize_fs.put(pickle.dumps('This is a test!'), filename='test_file_path')

        sanitized_dict = {'stub_plugin': {'result': 'test_file_path', 'file_system_flag': True},
                          'inbound_result': {'result': 'inbound result', 'file_system_flag': False}}
        retrieved_dict = self.db_interface.retrieve_analysis(sanitized_dict)

        assert 'file_system_flag' not in retrieved_dict['stub_plugin'].keys()
        assert 'result' in retrieved_dict['stub_plugin'].keys()
        assert retrieved_dict['stub_plugin']['result'] == 'This is a test!'
        assert 'file_system_flag' not in retrieved_dict['inbound_result'].keys()
        assert retrieved_dict['inbound_result']['result'] == 'inbound result'

    def test_retrieve_analysis_filter(self):
        self.db_interface.sanitize_fs.put(pickle.dumps('This is a test!'), filename='test_file_path')
        sanitized_dict = {'selected_plugin': {'result': 'test_file_path', 'file_system_flag': True},
                          'other_plugin': {'result': 'test_file_path', 'file_system_flag': True}}
        retrieved_dict = self.db_interface.retrieve_analysis(sanitized_dict, analysis_filter=['selected_plugin'])
        assert retrieved_dict['selected_plugin']['result'] == 'This is a test!'
        assert 'file_system_flag' in retrieved_dict['other_plugin']

    def test_get_objects_by_uid_list(self):
        self.db_interface_backend.add_firmware(self.test_firmware)
        fo_list = self.db_interface.get_objects_by_uid_list([self.test_firmware.uid])
        assert isinstance(fo_list[0], Firmware), 'firmware has wrong type'
        assert fo_list[0].device_name == 'test_router', 'Device name in Firmware not correct'
        test_file = FileObject(file_path=path.join(get_test_data_dir(), 'get_files_test/testfile2'))
        self.db_interface_backend.add_file_object(test_file)
        fo_list = self.db_interface.get_objects_by_uid_list([test_file.uid])
        assert isinstance(fo_list[0], FileObject), 'file object has wrong type'

    def test_sanitize_extract_and_retrieve_binary(self):
        test_data = {'dummy': {'test_key': 'test_value'}}
        test_data['dummy'] = self.db_interface._extract_binaries(test_data, 'dummy', 'uid')
        assert self.db_interface.sanitize_fs.list() == ['dummy_test_key_uid'], 'file not written'
        assert test_data['dummy']['test_key'] == 'dummy_test_key_uid', 'new file path not set'
        test_data['dummy'] = self.db_interface._retrieve_binaries(test_data, 'dummy')
        assert test_data['dummy']['test_key'] == 'test_value', 'value not recoverd'

    def test_get_firmware_number(self):
        result = self.db_interface.get_firmware_number()
        assert result == 0

        self.db_interface_backend.add_firmware(self.test_firmware)
        result = self.db_interface.get_firmware_number(query={})
        assert result == 1
        result = self.db_interface.get_firmware_number(query={'_id': self.test_firmware.uid})
        assert result == 1

        test_fw_2 = create_test_firmware(bin_path='container/test.7z')
        self.db_interface_backend.add_firmware(test_fw_2)
        result = self.db_interface.get_firmware_number(query='{}')
        assert result == 2
        result = self.db_interface.get_firmware_number(query={'_id': self.test_firmware.uid})
        assert result == 1

    def test_get_file_object_number(self):
        result = self.db_interface.get_file_object_number()
        assert result == 0

        self.db_interface_backend.add_file_object(self.test_fo)
        result = self.db_interface.get_file_object_number(query={}, zero_on_empty_query=False)
        assert result == 1
        result = self.db_interface.get_file_object_number(query={'_id': self.test_fo.uid})
        assert result == 1
        result = self.db_interface.get_file_object_number(query=json.dumps({'_id': self.test_fo.uid}))
        assert result == 1
        result = self.db_interface.get_file_object_number(query={}, zero_on_empty_query=True)
        assert result == 0
        result = self.db_interface.get_file_object_number(query='{}', zero_on_empty_query=True)
        assert result == 0

        test_fo_2 = create_test_file_object(bin_path='get_files_test/testfile2')
        self.db_interface_backend.add_file_object(test_fo_2)
        result = self.db_interface.get_file_object_number(query={}, zero_on_empty_query=False)
        assert result == 2
        result = self.db_interface.get_file_object_number(query={'_id': self.test_fo.uid})
        assert result == 1

    def test_unpacking_lock(self):
        first_uid, second_uid = 'id1', 'id2'
        assert not self.db_interface.check_unpacking_lock(first_uid) and not self.db_interface.check_unpacking_lock(second_uid), 'locks should not be set at start'

        self.db_interface.set_unpacking_lock(first_uid)
        assert self.db_interface.check_unpacking_lock(first_uid), 'locks should have been set'

        self.db_interface.set_unpacking_lock(second_uid)
        assert self.db_interface.check_unpacking_lock(first_uid) and self.db_interface.check_unpacking_lock(second_uid), 'both locks should be set'

        self.db_interface.release_unpacking_lock(first_uid)
        assert not self.db_interface.check_unpacking_lock(first_uid) and self.db_interface.check_unpacking_lock(second_uid), 'lock 1 should be released, lock 2 not'

        self.db_interface.drop_unpacking_locks()
        assert not self.db_interface.check_unpacking_lock(second_uid), 'all locks should be dropped'

    def test_lock_is_released(self):
        self.db_interface.set_unpacking_lock(self.test_fo.uid)
        assert self.db_interface.check_unpacking_lock(self.test_fo.uid), 'setting lock did not work'

        self.db_interface_backend.add_object(self.test_fo)
        assert not self.db_interface.check_unpacking_lock(self.test_fo.uid), 'add_object should release lock'

    def test_is_firmware(self):
        assert self.db_interface.is_firmware(self.test_firmware.uid) is False

        self.db_interface_backend.add_firmware(self.test_firmware)
        assert self.db_interface.is_firmware(self.test_firmware.uid) is True

    def test_is_file_object(self):
        assert self.db_interface.is_file_object(self.test_fo.uid) is False

        self.db_interface_backend.add_file_object(self.test_fo)
        assert self.db_interface.is_file_object(self.test_fo.uid) is True


@pytest.mark.usefixtures('use_db')
class TestSummary:

    def setup(self):
        self._config = get_config_for_testing(TMP_DIR)
        self.db_interface = MongoInterfaceCommon(config=self._config)
        self.db_interface_backend = BackEndDbInterface(config=self._config)

    def teardown(self):
        self.db_interface.client.drop_database(self._config.get('data_storage', 'main_database'))
        self.db_interface.shutdown()
        self.db_interface_backend.shutdown()
        TMP_DIR.cleanup()

    def create_and_add_test_fimrware_and_file_object(self):
        self.test_fw = create_test_firmware()
        self.test_fo = create_test_file_object()
        self.test_fw.add_included_file(self.test_fo)
        self.db_interface_backend.add_object(self.test_fw)
        self.db_interface_backend.add_object(self.test_fo)

    def test_get_set_of_all_included_files(self):
        self.create_and_add_test_fimrware_and_file_object()
        result_set_fo = self.db_interface.get_set_of_all_included_files(self.test_fo)
        assert isinstance(result_set_fo, set), 'result is not a set'
        assert len(result_set_fo) == 1, 'number of files not correct'
        assert self.test_fo.uid in result_set_fo, 'object not in its own result set'
        result_set_fw = self.db_interface.get_set_of_all_included_files(self.test_fw)
        assert len(result_set_fw) == 2, 'number of files not correct'
        assert self.test_fo.uid in result_set_fw, 'test file not in result set firmware'
        assert self.test_fw.uid in result_set_fw, 'fw not in result set firmware'

    def test_get_uids_of_all_included_files(self):
        def add_test_file_to_db_with_parent_uids(uid, parent_uids: Set[str]):
            test_fo = create_test_file_object()
            test_fo.parent_firmware_uids = parent_uids
            test_fo.uid = uid
            self.db_interface_backend.add_object(test_fo)
        add_test_file_to_db_with_parent_uids('uid1', {'foo'})
        add_test_file_to_db_with_parent_uids('uid2', {'foo', 'bar'})
        add_test_file_to_db_with_parent_uids('uid3', {'bar'})
        result = self.db_interface.get_uids_of_all_included_files('foo')
        assert result == {'uid1', 'uid2'}

        assert self.db_interface.get_uids_of_all_included_files('uid not in db') == set()

    def test_get_summary(self):
        self.create_and_add_test_fimrware_and_file_object()
        result_sum = self.db_interface.get_summary(self.test_fw, 'dummy')
        assert isinstance(result_sum, dict), 'summary is not a dict'
        assert 'sum a' in result_sum, 'summary entry of parent missing'
        assert self.test_fw.uid in result_sum['sum a'], 'origin (parent) missing in parent summary entry'
        assert self.test_fo.uid in result_sum['sum a'], 'origin (child) missing in parent summary entry'
        assert self.test_fo.uid not in result_sum['fw exclusive sum a'], 'child as origin but should not be'
        assert 'file exclusive sum b' in result_sum, 'file exclusive summary missing'
        assert self.test_fo.uid in result_sum['file exclusive sum b'], 'origin of file exclusive missing'
        assert self.test_fw.uid not in result_sum['file exclusive sum b'], 'parent as origin but should not be'

    def test_collect_summary(self):
        self.create_and_add_test_fimrware_and_file_object()
        fo_list = [self.test_fo.uid]
        result_sum = self.db_interface._collect_summary(fo_list, 'dummy')
        assert all(item in result_sum for item in self.test_fo.processed_analysis['dummy']['summary'])
        assert all(value == [self.test_fo.uid] for value in result_sum.values())

    def test_get_summary_of_one_error_handling(self):
        result_sum = self.db_interface._get_summary_of_one(None, 'foo')
        assert result_sum == {}, 'None object should result in empty dict'
        self.create_and_add_test_fimrware_and_file_object()
        result_sum = self.db_interface._get_summary_of_one(self.test_fw, 'none_existing_analysis')
        assert result_sum == {}, 'analysis not existend should lead to empty dict'

    def test_update_summary(self):
        orig = {'a': ['a']}
        update = {'a': ['aa'], 'b': ['aa']}
        result = self.db_interface._update_summary(orig, update)
        assert 'a' in result
        assert 'b' in result
        assert 'a' in result['a']
        assert 'aa' in result['a']
        assert 'aa' in result['b']

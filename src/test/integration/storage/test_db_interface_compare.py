# pylint: disable=attribute-defined-outside-init,protected-access
import gc
from time import time

import pytest

from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_backend import BackEndDbInterface
from storage.db_interface_common import MongoInterfaceCommon
from storage.db_interface_compare import CompareDbInterface, FactCompareException
from storage.MongoMgr import MongoMgr
from test.common_helper import create_test_firmware, get_config_for_testing


class TestCompare:

    @classmethod
    def setup_class(cls):
        cls._config = get_config_for_testing()
        cls.mongo_server = MongoMgr(config=cls._config)

    def setup(self):
        self.db_interface = MongoInterfaceCommon(config=self._config)
        self.db_interface_backend = BackEndDbInterface(config=self._config)
        self.db_interface_compare = CompareDbInterface(config=self._config)
        self.db_interface_admin = AdminDbInterface(config=self._config)

        self.fw_one = create_test_firmware()
        self.fw_two = create_test_firmware()
        self.fw_two.set_binary(b'another firmware')
        self.compare_dict = self._create_compare_dict()
        self.compare_id = '{};{}'.format(self.fw_one.uid, self.fw_two.uid)

    def teardown(self):
        self.db_interface_compare.shutdown()
        self.db_interface_admin.shutdown()
        self.db_interface_backend.shutdown()
        self.db_interface.client.drop_database(self._config.get('data_storage', 'main_database'))
        self.db_interface.shutdown()
        gc.collect()

    @classmethod
    def teardown_class(cls):
        cls.mongo_server.shutdown()

    def _create_compare_dict(self):
        return {
            'general': {
                'hid': {self.fw_one.uid: 'foo', self.fw_two.uid: 'bar'},
                'virtual_file_path': {self.fw_one.uid: 'dev_one_name', self.fw_two.uid: 'dev_two_name'}
            },
            'plugins': {},
        }

    def test_add_and_get_compare_result(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        self.db_interface_compare.add_compare_result(self.compare_dict)
        retrieved = self.db_interface_compare.get_compare_result(self.compare_id)
        assert retrieved['general']['virtual_file_path'][self.fw_one.uid] == 'dev_one_name',\
            'content of retrieval not correct'

    def test_get_not_existing_compare_result(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        result = self.db_interface_compare.get_compare_result(self.compare_id)
        assert result is None, 'result not none'

    def test_calculate_compare_result_id(self):
        comp_id = self.db_interface_compare._calculate_compare_result_id(self.compare_dict)
        assert comp_id == self.compare_id

    def test_calculate_compare_result_id__incomplete_entries(self):
        compare_dict = {'general': {'stat_1': {'a': None}, 'stat_2': {'b': None}}}
        comp_id = self.db_interface_compare._calculate_compare_result_id(compare_dict)
        assert comp_id == 'a;b'

    def test_check_objects_exist(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        assert not self.db_interface_compare.check_objects_exist(self.fw_one.uid), 'existing_object not found'
        with pytest.raises(FactCompareException):
            self.db_interface_compare.check_objects_exist('{};none_existing_object'.format(self.fw_one.uid))

    def test_get_compare_result_of_nonexistent_uid(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        try:
            self.db_interface_compare.check_objects_exist('{};none_existing_object'.format(self.fw_one.uid))
        except FactCompareException as exception:
            assert exception.get_message() == 'none_existing_object not found in database', 'error message not correct'

    def test_get_latest_comparisons(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        before = time()
        self.db_interface_compare.add_compare_result(self.compare_dict)
        result = self.db_interface_compare.page_compare_results(limit=10)
        for id_, hids, submission_date in result:
            assert self.fw_one.uid in hids
            assert self.fw_two.uid in hids
            assert self.fw_one.uid in id_
            assert self.fw_two.uid in id_
            assert before <= submission_date <= time()

    def test_get_latest_comparisons_removed_firmware(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        self.db_interface_compare.add_compare_result(self.compare_dict)

        result = self.db_interface_compare.page_compare_results(limit=10)
        assert result != [], 'A compare result should be available'

        self.db_interface_admin.delete_firmware(self.fw_two.uid)

        result = self.db_interface_compare.page_compare_results(limit=10)

        assert result == [], 'No compare result should be available'

    def test_get_total_number_of_results(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        self.db_interface_compare.add_compare_result(self.compare_dict)

        number = self.db_interface_compare.get_total_number_of_results()
        assert number == 1, 'no compare result found in database'

    @pytest.mark.parametrize('root_uid, expected_result', [
        ('the_root_uid', ['uid1', 'uid2']),
        ('some_other_uid', []),
        (None, []),
    ])
    def test_get_exclusive_files(self, root_uid, expected_result):
        compare_dict = self._create_compare_dict()
        compare_dict['plugins'] = {'File_Coverage': {'exclusive_files': {'the_root_uid': ['uid1', 'uid2']}}}

        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        self.db_interface_compare.add_compare_result(compare_dict)
        exclusive_files = self.db_interface_compare.get_exclusive_files(self.compare_id, root_uid)
        assert exclusive_files == expected_result

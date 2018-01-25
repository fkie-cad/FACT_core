import gc
from time import time
import unittest

from helperFunctions.config import get_config_for_testing
from storage.MongoMgr import MongoMgr
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_backend import BackEndDbInterface
from storage.db_interface_common import MongoInterfaceCommon
from storage.db_interface_compare import CompareDbInterface
from test.common_helper import create_test_firmware


class TestCompare(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls._config = get_config_for_testing()
        cls.mongo_server = MongoMgr(config=cls._config)

    def setUp(self):
        self.db_interface = MongoInterfaceCommon(config=self._config)
        self.db_interface_backend = BackEndDbInterface(config=self._config)
        self.db_interface_compare = CompareDbInterface(config=self._config)
        self.db_interface_admin = AdminDbInterface(config=self._config)

        self.fw_one = create_test_firmware()
        self.fw_two = create_test_firmware()
        self.fw_two.set_binary(b'another firmware')
        self.compare_dict = self._create_compare_dict()

    def tearDown(self):
        self.db_interface_compare.shutdown()
        self.db_interface_admin.shutdown()
        self.db_interface_backend.shutdown()
        self.db_interface.client.drop_database(self._config.get('data_storage', 'main_database'))
        self.db_interface.shutdown()
        gc.collect()

    @classmethod
    def tearDownClass(cls):
        cls.mongo_server.shutdown()

    def _create_compare_dict(self):
        comp_dict = {'general': {'hid': {self.fw_one.get_uid(): 'foo', self.fw_two.get_uid(): 'bar'}}, 'plugins': {}}
        comp_dict['general']['virtual_file_path'] = {self.fw_one.get_uid(): 'dev_one_name', self.fw_two.get_uid(): 'dev_two_name'}
        return comp_dict

    def test_add_and_get_compare_result(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        self.db_interface_compare.add_compare_result(self.compare_dict)
        retrieved = self.db_interface_compare.get_compare_result('{};{}'.format(self.fw_one.get_uid(), self.fw_two.get_uid()))
        self.assertEqual(retrieved['general']['virtual_file_path'][self.fw_one.get_uid()], 'dev_one_name',
                         'content of retrieval not correct')

    def test_get_not_existing_compare_result(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        result = self.db_interface_compare.get_compare_result('{};{}'.format(self.fw_one.get_uid(), self.fw_two.get_uid()))
        self.assertIsNone(result, 'result not none')

    def test_calculate_compare_result_id(self):
        comp_id = self.db_interface_compare._calculate_compare_result_id(self.compare_dict)
        self.assertEqual(comp_id, '{};{}'.format(self.fw_one.get_uid(), self.fw_two.get_uid()))

    def test_calculate_compare_result_id__incomplete_entries(self):
        compare_dict = {'general': {'stat_1': {'a': None}, 'stat_2': {'b': None}}}
        comp_id = self.db_interface_compare._calculate_compare_result_id(compare_dict)
        self.assertEqual('a;b', comp_id)

    def test_object_existence_quick_check(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.assertIsNone(self.db_interface_compare.object_existence_quick_check(self.fw_one.get_uid()), 'existing_object not found')
        self.assertEqual(self.db_interface_compare.object_existence_quick_check('{};none_existing_object'.format(self.fw_one.get_uid())), 'none_existing_object not found in database', 'error message not correct')

    def test_get_compare_result_of_none_existing_uid(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        result = self.db_interface_compare.get_compare_result('{};none_existing_uid'.format(self.fw_one.get_uid()))
        self.assertEqual(result, 'none_existing_uid not found in database', 'no result not found error')

    def test_get_latest_comparisons(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        before = time()
        self.db_interface_compare.add_compare_result(self.compare_dict)
        result = self.db_interface_compare.page_compare_results(limit=10)
        for id, hids, submission_date in result:
            self.assertIn(self.fw_one.get_uid(), hids)
            self.assertIn(self.fw_two.get_uid(), hids)
            self.assertIn(self.fw_one.get_uid(), id)
            self.assertIn(self.fw_two.get_uid(), id)
            self.assertTrue(before <= submission_date <= time())

    def test_get_latest_comparisons_removed_firmware(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        self.db_interface_compare.add_compare_result(self.compare_dict)

        result = self.db_interface_compare.page_compare_results(limit=10)
        self.assertNotEqual(result, [], 'A compare result should be available')

        self.db_interface_admin.delete_firmware(self.fw_two.uid)

        result = self.db_interface_compare.page_compare_results(limit=10)

        self.assertEqual(result, [], 'No compare result should be available')

    def test_get_total_number_of_results(self):
        self.db_interface_backend.add_firmware(self.fw_one)
        self.db_interface_backend.add_firmware(self.fw_two)
        self.db_interface_compare.add_compare_result(self.compare_dict)

        number = self.db_interface_compare.get_total_number_of_results()
        self.assertEqual(number, 1, 'no compare result found in database')

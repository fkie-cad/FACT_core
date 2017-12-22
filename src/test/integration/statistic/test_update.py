import gc
import unittest

from helperFunctions.config import get_config_for_testing
from statistic.update import StatisticUpdater
from storage.MongoMgr import MongoMgr
from storage.db_interface_statistic import StatisticDbViewer
from test.common_helper import get_database_names
from test.unit.helperFunctions_setup_test_data import clean_test_database


class TestStatistic(unittest.TestCase):

    def setUp(self):
        self.config = get_config_for_testing()
        self.mongo_server = MongoMgr(config=self.config)
        self.updater = StatisticUpdater(config=self.config)
        self.frontend_db_interface = StatisticDbViewer(config=self.config)

    def tearDown(self):
        self.updater.shutdown()
        self.frontend_db_interface.shutdown()
        clean_test_database(self.config, get_database_names(self.config))
        self.mongo_server.shutdown()
        gc.collect()

    def test_update_and_get_statistic(self):
        self.updater.db.update_statistic('test', {'test1': 1})
        result = self.frontend_db_interface.get_statistic('test')
        self.assertEqual(result['test1'], 1, 'result not correct')
        self.updater.db.update_statistic('test', {'test1': 2})
        result = self.frontend_db_interface.get_statistic('test')
        self.assertEqual(result['test1'], 2, 'result not correct')

    def test_get_general_stats(self):
        result = self.updater.get_general_stats()
        self.assertEqual(result['number_of_firmwares'], 0, 'number of firmwares not correct')
        self.assertEqual(result['number_of_unique_files'], 0, 'number of files not correct')
        self.updater.db.firmwares.insert_one({'test': 1})
        self.updater.db.file_objects.insert_one({'test': 1})
        result = self.updater.get_general_stats()
        self.assertEqual(result['number_of_firmwares'], 1, 'number of firmwares not correct')
        self.assertEqual(result['number_of_unique_files'], 1, 'number of files not correct')

    def test_convert_dict_list_to_list(self):
        test_list = [{'count': 1, '_id': 'A'}, {'count': 2, '_id': 'B'}, {'count': 3, '_id': None}]
        result = self.updater._convert_dict_list_to_list(test_list)
        self.assertIsInstance(result, list, 'result is not a list')
        self.assertIn(['A', 1], result)
        self.assertIn(['B', 2], result)
        self.assertIn(['not available', 3], result)
        self.assertEqual(len(result), 3, 'too many keys in the result')

    def test_filter_sanitized_entries(self):
        test_list = [['valid', 1], ['sanitized_81abfc7a79c8c1ed85f6b9fc2c5d9a3edc4456c4aecb9f95b4d7a2bf9bf652da_1', 1]]
        result = self.updater._filter_sanitzized_objects(test_list)
        self.assertEqual(result, [['valid', 1]])

    def test_find_most_frequent_architecture(self):
        test_list = ['MIPS, 32-bit, big endian (M)', 'MIPS (M)', 'MIPS, 32-bit, big endian (M)', 'MIPS, 32-bit, big endian (M)']
        result = self.updater._find_most_frequent_architecture(test_list)
        expected_result = 'MIPS, 32-bit, big endian (M)'
        self.assertEqual(result, expected_result)
        test_list = ['A', 'B', 'B', 'B', 'C', 'C']
        result = self.updater._find_most_frequent_architecture(test_list)
        expected_result = 'B'
        self.assertEqual(result, expected_result)

    def test_count_occurrences(self):
        test_list = ['A', 'B', 'B', 'C', 'C', 'C']
        result = set(self.updater._count_occurrences(test_list))
        expected_result = {('A', 1), ('C', 3), ('B', 2)}
        self.assertEqual(result, expected_result)

    def test_shorten_architecture_string(self):
        tests_string = 'MIPS, 64-bit, little endian (M)'
        result = self.updater._shorten_architecture_string(tests_string)
        self.assertEqual(result, 'MIPS, 64-bit')
        tests_string = 'MIPS (M)'
        result = self.updater._shorten_architecture_string(tests_string)
        self.assertEqual(result, 'MIPS')

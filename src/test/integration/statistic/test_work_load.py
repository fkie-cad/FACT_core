import unittest

from helperFunctions.config import get_config_for_testing
from storage.MongoMgr import MongoMgr

from storage.db_interface_statistic import StatisticDbViewer
from test.unit.helperFunctions_setup_test_data import clean_test_database
from statistic.work_load import WorkLoadStatistic
from time import time


class TestWorkloadStatistic(unittest.TestCase):

    def setUp(self):
        self.config = get_config_for_testing()
        self.mongo_server = MongoMgr(config=self.config)
        self.workload_stat = WorkLoadStatistic(config=self.config, component='test')
        self.frontend_db_interface = StatisticDbViewer(config=self.config)

    def tearDown(self):
        clean_test_database(self.config, [self.config.get('data_storage', 'statistic_database'), self.config.get('data_storage', 'main_database')])
        self.workload_stat.shutdown()
        self.frontend_db_interface.shutdown()
        self.mongo_server.shutdown()

    def test_update_workload_statistic(self):
        self.workload_stat.update()
        result = self.frontend_db_interface.get_statistic('test')
        self.assertEqual(result['name'], 'test', 'name not set')
        self.assertAlmostEqual(time(), result['last_update'], msg='timestamp not valid', delta=100)
        self.assertIsInstance(result['platform'], dict, 'platfom is not a dict')
        self.assertIsInstance(result['system'], dict, 'system is not a dict')

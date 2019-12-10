import gc
import unittest
from time import time

from statistic.work_load import WorkLoadStatistic
from storage.db_interface_statistic import StatisticDbViewer
from storage.MongoMgr import MongoMgr
from test.common_helper import clean_test_database, get_config_for_testing, get_database_names


class TestWorkloadStatistic(unittest.TestCase):

    def setUp(self):
        self.config = get_config_for_testing()
        self.mongo_server = MongoMgr(config=self.config)
        self.workload_stat = WorkLoadStatistic(config=self.config, component='test')
        self.frontend_db_interface = StatisticDbViewer(config=self.config)

    def tearDown(self):
        self.frontend_db_interface.shutdown()
        self.workload_stat.shutdown()
        clean_test_database(self.config, get_database_names(self.config))
        self.mongo_server.shutdown()
        gc.collect()

    def test_update_workload_statistic(self):
        self.workload_stat.update()
        result = self.frontend_db_interface.get_statistic('test')
        self.assertEqual(result['name'], 'test', 'name not set')
        self.assertAlmostEqual(time(), result['last_update'], msg='timestamp not valid', delta=100)
        self.assertIsInstance(result['platform'], dict, 'platfom is not a dict')
        self.assertIsInstance(result['system'], dict, 'system is not a dict')

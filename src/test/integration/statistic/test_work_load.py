import gc
from math import isclose
from time import time

import pytest

from config import configparser_cfg
from statistic.work_load import WorkLoadStatistic
from storage.db_interface_stats import StatsDbViewer


@pytest.mark.usefixtures('patch_cfg')
class TestWorkloadStatistic:

    def setup(self):
        self.workload_stat = WorkLoadStatistic(config=configparser_cfg, component='test')
        self.stats_db = StatsDbViewer(config=configparser_cfg)

    def teardown(self):
        self.workload_stat.shutdown()
        gc.collect()

    def test_update_workload_statistic(self, db):
        self.workload_stat.update()
        result = self.stats_db.get_statistic('test')
        assert result['name'] == 'test', 'name not set'
        assert isclose(time(), result['last_update'], abs_tol=0.1), 'timestamp not valid'
        assert isinstance(result['platform'], dict), 'platform is not a dict'
        assert isinstance(result['system'], dict), 'system is not a dict'

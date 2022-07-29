import gc
from math import isclose
from time import time

from statistic.work_load import WorkLoadStatistic
from storage.db_interface_stats import StatsDbViewer
from test.common_helper import get_config_for_testing  # pylint: disable=wrong-import-order


class TestWorkloadStatistic:
    def setup(self):
        self.config = get_config_for_testing()
        self.workload_stat = WorkLoadStatistic(config=self.config, component='test')
        self.workload_stat.start()
        self.stats_db = StatsDbViewer(config=self.config)

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

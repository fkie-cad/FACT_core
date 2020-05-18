# pylint:disable=attribute-defined-outside-init

import gc
from math import isclose
from time import time

import pytest

from statistic.work_load import WorkLoadStatistic
from storage.db_interface_statistic import StatisticDbViewer
from test.common_helper import clean_test_database, get_config_for_testing, get_database_names


@pytest.mark.usefixtures('use_db')
class TestWorkloadStatistic:

    def setup(self):
        self.config = get_config_for_testing()
        self.workload_stat = WorkLoadStatistic(config=self.config, component='test')
        self.frontend_db_interface = StatisticDbViewer(config=self.config)

    def teardown(self):
        self.frontend_db_interface.shutdown()
        self.workload_stat.shutdown()
        clean_test_database(self.config, get_database_names(self.config))
        gc.collect()

    def test_update_workload_statistic(self):
        self.workload_stat.update()
        result = self.frontend_db_interface.get_statistic('test')
        assert result['name'] == 'test', 'name not set'
        assert isclose(time(), result['last_update'], abs_tol=100), 'timestamp not valid'
        assert isinstance(result['platform'], dict), 'platform is not a dict'
        assert isinstance(result['system'], dict), 'system is not a dict'

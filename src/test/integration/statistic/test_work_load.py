from math import isclose
from time import time

import pytest

from statistic.work_load import WorkLoadStatistic
from storage.db_interface_stats import StatsDbViewer


@pytest.fixture
def workload_stat():
    workload_stat = WorkLoadStatistic(component='test')
    yield workload_stat
    workload_stat.shutdown()


@pytest.fixture
def stats_db():
    yield StatsDbViewer()


def test_update_workload_statistic(db, workload_stat, stats_db):
    workload_stat.update()
    result = stats_db.get_statistic('test')
    assert result['name'] == 'test', 'name not set'
    assert isclose(time(), result['last_update'], abs_tol=0.1), 'timestamp not valid'
    assert isinstance(result['platform'], dict), 'platform is not a dict'
    assert isinstance(result['system'], dict), 'system is not a dict'

from math import isclose
from time import time

import pytest

from statistic.work_load import WorkLoadStatistic
from storage.db_interface_stats import StatsDbViewer
from storage.redis_status_interface import RedisStatusInterface


@pytest.fixture
def workload_stat():
    workload_stat = WorkLoadStatistic(component='frontend')
    yield workload_stat
    workload_stat.shutdown()


@pytest.fixture
def stats_db():
    return StatsDbViewer()


@pytest.mark.usefixtures('database_interfaces')
def test_update_workload_statistic(workload_stat):
    workload_stat.update()
    status = RedisStatusInterface()
    result = status.get_component_status('frontend')
    assert result['name'] == 'frontend', 'name not set'
    assert isclose(time(), result['last_update'], abs_tol=0.1), 'timestamp not valid'
    assert isinstance(result['platform'], dict), 'platform is not a dict'
    assert isinstance(result['system'], dict), 'system is not a dict'

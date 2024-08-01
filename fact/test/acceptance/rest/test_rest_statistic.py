import pytest

from statistic.work_load import WorkLoadStatistic


@pytest.fixture
def workload_statistic():
    _workload_statistic = WorkLoadStatistic(component='backend')
    yield _workload_statistic
    _workload_statistic.shutdown()


class TestRestStatistic:
    @pytest.mark.usefixtures('intercom_backend_binding')
    def test_status(self, test_client, workload_statistic, unpacking_scheduler, analysis_scheduler):
        workload_statistic.update(
            unpacking_workload=unpacking_scheduler.get_scheduled_workload(),
            analysis_workload=analysis_scheduler.get_scheduled_workload(),
        )

        rv = test_client.get('/rest/status', follow_redirects=True)

        assert rv.status_code == 200  # noqa: PLR2004
        assert all(key in rv.json for key in ['system_status', 'plugins'])
        assert 'backend' in rv.json['system_status']
        assert rv.json['system_status']['backend']['status'] == 'online'
        assert rv.json['system_status']['backend']['analysis']['plugins']['file_type']['queue'] == 0

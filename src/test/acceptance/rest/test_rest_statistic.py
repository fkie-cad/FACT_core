import pytest

from statistic.work_load import WorkLoadStatistic


@pytest.fixture
def workload(cfg_tuple):
    _, configparser_cfg = cfg_tuple
    wl = WorkLoadStatistic(config=configparser_cfg, component='backend')

    yield wl

    wl.shutdown()


def test_status(backend_services, test_client, workload):
    workload.update(unpacking_workload=backend_services.unpacking_service.get_scheduled_workload(), analysis_workload=backend_services.analysis_service.get_scheduled_workload())

    rv = test_client.get('/rest/status', follow_redirects=True)

    assert rv.status_code == 200
    assert all(key in rv.json for key in ['system_status', 'plugins'])
    assert 'backend' in rv.json['system_status']
    assert rv.json['system_status']['backend']['status'] == 'online'
    assert rv.json['system_status']['backend']['analysis']['plugins']['file_type']['queue'] == 0

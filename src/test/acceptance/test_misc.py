# pylint: disable=wrong-import-order
import json
import os
import time
from urllib.parse import quote
import pytest

from statistic.update import StatsUpdater
from statistic.work_load import WorkLoadStatistic
from test.common_helper import get_test_data_dir

from test.acceptance.conftest import SchedulerAcceptanceTestConfig


@pytest.fixture(autouse=True)
def _autouse_intercom_backend_binding(intercom_backend_binding):
    pass


@pytest.fixture
def stats_updater():
    return StatsUpdater()


@pytest.fixture
def workload_statistic():
    return WorkLoadStatistic(component='backend')


def _upload_firmware_get(test_client):
    rv = test_client.get('/upload')
    assert b'<h3 class="mb-3">Upload Firmware</h3>' in rv.data, 'upload page not displayed correctly'


def _upload_firmware_put(test_client, path, device_name, uid):
    testfile_path = os.path.join(get_test_data_dir(), path)
    with open(testfile_path, 'rb') as fp:
        data = {
            'file': fp,
            'device_name': device_name,
            'device_part': 'full',
            'device_class': 'test_class',
            'version': '1.0',
            'vendor': 'test_vendor',
            'release_date': '2009-01-01',
            'tags': '',
            'analysis_systems': [],
        }
        rv = test_client.post('/upload', content_type='multipart/form-data', data=data, follow_redirects=True)
    assert b'Upload Successful' in rv.data, 'upload not successful'
    assert uid.encode() in rv.data, 'uid not found on upload success page'


def _show_stats(test_client):
    rv = test_client.get('/statistic')
    assert b'Firmware Container' in rv.data
    assert b'test_vendor' in rv.data
    assert b'Release Date Stats' in rv.data


def _show_stats_filtered(test_client):
    rv = test_client.get('/statistic?vendor=test_vendor')
    assert b'Firmware Container' in rv.data
    assert b'test_vendor' in rv.data
    assert b'Release Date Stats' in rv.data


def _show_about(test_client):
    rv = test_client.get('/about')
    assert b'License Information' in rv.data


def _show_home(test_client):
    rv = test_client.get('/')
    assert b'backend cpu load' in rv.data


def _show_system_monitor(test_client):
    rv = test_client.get('/system_health')
    assert b'backend status' in rv.data


def _click_chart(test_client, test_fw_a):
    query = json.dumps({'vendor': 'test_vendor'})
    rv = test_client.get(f'/database/browse?query={quote(query)}')
    assert test_fw_a.uid.encode() in rv.data


def _click_release_date_histogram(test_client, test_fw_a):
    rv = test_client.get('/database/browse?date="January 2009"')
    assert test_fw_a.uid.encode() in rv.data


@pytest.mark.skip(reason="TODO should work")
@pytest.mark.SchedulerTestConfig(
    SchedulerAcceptanceTestConfig(
        # two firmware container with 3 included files each times two mandatory plugins
        items_to_analyze=4
        * 2
        * 2,
    ),
)
def test_misc(
    test_client,
    intercom_backend_binding,
    workload_statistic,
    unpacking_scheduler,
    analysis_scheduler,
    test_fw_a,
    test_fw_c,
    analysis_finished_event,
    stats_updater,
):
    _upload_firmware_get(test_client)
    for fw in [test_fw_a, test_fw_c]:
        _upload_firmware_put(test_client, fw.path, fw.name, fw.uid)
    _show_about(test_client)
    time.sleep(4)
    workload_statistic.update(
        unpacking_workload=unpacking_scheduler.get_scheduled_workload(),
        analysis_workload=analysis_scheduler.get_scheduled_workload(),
    )
    analysis_finished_event.wait(timeout=10)
    _show_system_monitor(test_client)

    stats_updater.update_all_stats()

    _show_stats(test_client)
    _show_stats_filtered(test_client)
    _click_chart(test_client, test_fw_a)
    _click_release_date_histogram(test_client, test_fw_a)

    _show_home(test_client)

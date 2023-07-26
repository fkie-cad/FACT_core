import json
import os
import time
from urllib.parse import quote

import pytest

from statistic.update import StatsUpdater
from statistic.work_load import WorkLoadStatistic
from test.acceptance.conftest import test_fw_a, test_fw_c
from test.common_helper import get_test_data_dir


@pytest.fixture(autouse=True)
def _autouse_intercom_backend_binding(intercom_backend_binding):  # noqa: ARG001
    pass


@pytest.fixture
def stats_updater():
    return StatsUpdater()


@pytest.fixture
def workload_statistic():
    return WorkLoadStatistic(component='backend')


class TestAcceptanceMisc:
    def _upload_firmware_get(self, test_client):
        rv = test_client.get('/upload')
        assert b'<h3 class="mb-3">Upload Firmware</h3>' in rv.data, 'upload page not displayed correctly'

    def _upload_firmware_put(self, test_client, path, device_name, uid):
        testfile_path = os.path.join(get_test_data_dir(), path)  # noqa: PTH118
        with open(testfile_path, 'rb') as fp:  # noqa: PTH123
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

    def _show_stats(self, test_client):
        rv = test_client.get('/statistic')
        assert b'Firmware Container' in rv.data
        assert b'test_vendor' in rv.data
        assert b'Release Date Stats' in rv.data

    def _show_stats_filtered(self, test_client):
        rv = test_client.get('/statistic?vendor=test_vendor')
        assert b'Firmware Container' in rv.data
        assert b'test_vendor' in rv.data
        assert b'Release Date Stats' in rv.data

    def _show_about(self, test_client):
        rv = test_client.get('/about')
        assert b'License Information' in rv.data

    def _show_home(self, test_client):
        rv = test_client.get('/')
        assert b'backend cpu load' in rv.data
        assert b'test comment' in rv.data
        assert (
            rv.data.count(f'onclick="location.href=\'/analysis/{test_fw_a.uid}\'"'.encode()) == 2  # noqa: PLR2004
        ), 'There should be two analysis links: one for latest comments and one for latest submissions'

    def _show_system_monitor(self, test_client):
        rv = test_client.get('/system_health')
        assert b'backend status' in rv.data

    def _click_chart(self, test_client):
        query = json.dumps({'vendor': 'test_vendor'})
        rv = test_client.get(f'/database/browse?query={quote(query)}')
        assert test_fw_a.uid.encode() in rv.data

    def _click_release_date_histogram(self, test_client):
        rv = test_client.get('/database/browse?date="January 2009"')
        assert test_fw_a.uid.encode() in rv.data

    def _add_comment(self, test_client):
        data = {'comment': 'this is the test comment', 'author': 'test author'}
        test_client.post(
            f'/comment/{test_fw_a.uid}', content_type='multipart/form-data', data=data, follow_redirects=True
        )

    @pytest.mark.SchedulerTestConfig(
        # fmt: off
        # two firmware container with 3 included files each times two mandatory plugins
        items_to_analyze=4 * 2 * 2,
    )
    @pytest.mark.usefixtures('intercom_backend_binding')
    def test_misc(  # noqa: PLR0913
        self,
        test_client,
        workload_statistic,
        unpacking_scheduler,
        analysis_scheduler,
        analysis_finished_event,
        stats_updater,
    ):
        self._upload_firmware_get(test_client)
        for fw in [test_fw_a, test_fw_c]:
            self._upload_firmware_put(test_client, fw.path, fw.name, fw.uid)
        self._show_about(test_client)
        time.sleep(4)
        workload_statistic.update(
            unpacking_workload=unpacking_scheduler.get_scheduled_workload(),
            analysis_workload=analysis_scheduler.get_scheduled_workload(),
        )
        assert analysis_finished_event.wait(timeout=10)
        self._show_system_monitor(test_client)

        stats_updater.update_all_stats()

        self._show_stats(test_client)
        self._show_stats_filtered(test_client)
        self._click_chart(test_client)
        self._click_release_date_histogram(test_client)

        self._add_comment(test_client)
        self._show_home(test_client)

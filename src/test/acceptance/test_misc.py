# pylint: disable=no-self-use
# pylint: disable=wrong-import-order
import json
import os
import time
from urllib.parse import quote

from statistic.update import StatsUpdater
from statistic.work_load import WorkLoadStatistic
from test.common_helper import get_test_data_dir


class TestAcceptanceMisc:
    def _upload_firmware_get(self, test_client):
        rv = test_client.get('/upload')
        assert b'<h3 class="mb-3">Upload Firmware</h3>' in rv.data, 'upload page not displayed correctly'

    def _upload_firmware_put(self, test_client, path, device_name, uid):
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
                'analysis_systems': []
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

    def _show_system_monitor(self, test_client):
        rv = test_client.get('/system_health')
        assert b'backend status' in rv.data

    def _click_chart(self, test_client, test_fw_a):
        query = json.dumps({'vendor': 'test_vendor'})
        rv = test_client.get(f'/database/browse?query={quote(query)}')
        assert test_fw_a.uid.encode() in rv.data

    def _click_release_date_histogram(self, test_client, test_fw_a):
        rv = test_client.get('/database/browse?date="January 2009"')
        assert test_fw_a.uid.encode() in rv.data

    def test_misc(self, backend_services, test_client, analysis_finished_event, test_fw_a, test_fw_c, cfg_tuple):
        _, configparser_cfg = cfg_tuple
        updater = StatsUpdater(config=configparser_cfg)
        workload = WorkLoadStatistic(config=configparser_cfg, component='backend')

        self._upload_firmware_get(test_client)
        for fw in [test_fw_a, test_fw_c]:
            self._upload_firmware_put(test_client, fw.path, fw.name, fw.uid)
        self._show_about(test_client)
        time.sleep(4)
        workload.update(
            unpacking_workload=backend_services.unpacking_service.get_scheduled_workload(),
            analysis_workload=backend_services.analysis_service.get_scheduled_workload(),
        )
        analysis_finished_event.wait(timeout=10)
        self._show_system_monitor(test_client)

        updater.update_all_stats()

        self._show_stats(test_client)
        self._show_stats_filtered(test_client)
        self._click_chart(test_client, test_fw_a)
        self._click_release_date_histogram(test_client, test_fw_a)

        self._show_home(test_client)

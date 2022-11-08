# pylint: disable=wrong-import-order
import json
import os
import time
from multiprocessing import Event, Value
from urllib.parse import quote

import pytest

from statistic.update import StatsUpdater
from statistic.work_load import WorkLoadStatistic
from storage.db_interface_backend import BackendDbInterface
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import get_test_data_dir


class TestAcceptanceMisc(TestAcceptanceBase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.analysis_finished_event = Event()
        cls.elements_finished_analyzing = Value('i', 0)

    def setUp(self):
        super().setUp()
        self._start_backend(post_analysis=self._analysis_callback)
        self.updater = StatsUpdater()
        self.workload = WorkLoadStatistic(component='backend')
        time.sleep(2)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()

    def _analysis_callback(self, uid: str, plugin: str, analysis_dict: dict):
        db_backend_service = BackendDbInterface()
        db_backend_service.add_analysis(uid, plugin, analysis_dict)
        self.elements_finished_analyzing.value += 1
        if (
            self.elements_finished_analyzing.value == 4 * 2 * 2
        ):  # two firmware container with 3 included files each times two mandatory plugins
            self.analysis_finished_event.set()

    def _upload_firmware_get(self):
        rv = self.test_client.get('/upload')
        self.assertIn(b'<h3 class="mb-3">Upload Firmware</h3>', rv.data, 'upload page not displayed correctly')

    def _upload_firmware_put(self, path, device_name, uid):
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
            rv = self.test_client.post('/upload', content_type='multipart/form-data', data=data, follow_redirects=True)
        self.assertIn(b'Upload Successful', rv.data, 'upload not successful')
        self.assertIn(uid.encode(), rv.data, 'uid not found on upload success page')

    def _show_stats(self):
        rv = self.test_client.get('/statistic')
        self.assertIn(b'Firmware Container', rv.data)
        self.assertIn(b'test_vendor', rv.data)
        self.assertIn(b'Release Date Stats', rv.data)

    def _show_stats_filtered(self):
        rv = self.test_client.get('/statistic?vendor=test_vendor')
        self.assertIn(b'Firmware Container', rv.data)
        self.assertIn(b'test_vendor', rv.data)
        self.assertIn(b'Release Date Stats', rv.data)

    def _show_about(self):
        rv = self.test_client.get('/about')
        self.assertIn(b'License Information', rv.data)

    def _show_home(self):
        rv = self.test_client.get('/')
        self.assertIn(b'backend cpu load', rv.data)

    def _show_system_monitor(self):
        rv = self.test_client.get('/system_health')
        self.assertIn(b'backend status', rv.data)

    def _click_chart(self):
        query = json.dumps({'vendor': 'test_vendor'})
        rv = self.test_client.get(f'/database/browse?query={quote(query)}')
        self.assertIn(self.test_fw_a.uid.encode(), rv.data)

    def _click_release_date_histogram(self):
        rv = self.test_client.get('/database/browse?date="January 2009"')
        self.assertIn(self.test_fw_a.uid.encode(), rv.data)

    def test_misc(self):
        self._upload_firmware_get()
        for fw in [self.test_fw_a, self.test_fw_c]:
            self._upload_firmware_put(fw.path, fw.name, fw.uid)
        self._show_about()
        time.sleep(4)
        self.workload.update(
            unpacking_workload=self.unpacking_service.get_scheduled_workload(),
            analysis_workload=self.analysis_service.get_scheduled_workload(),
        )
        self.analysis_finished_event.wait(timeout=10)
        self._show_system_monitor()

        self.updater.update_all_stats()

        self._show_stats()
        self._show_stats_filtered()
        self._click_chart()
        self._click_release_date_histogram()

        self._show_home()

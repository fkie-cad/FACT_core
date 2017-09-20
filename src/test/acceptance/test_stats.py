import os
import time

from test.acceptance.base import TestAcceptanceBase
from helperFunctions.fileSystem import get_test_data_dir
from statistic.update import StatisticUpdater


class TestAcceptanceShowStats(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.updater = StatisticUpdater(config=self.config)
        time.sleep(10)  # wait for systems to start

    def tearDown(self):
        super().tearDown()
        self._stop_backend()

    def _upload_firmware_get(self):
        rv = self.test_client.get('/upload')
        self.assertIn(b'<h2>Upload Firmware</h2>', rv.data, "upload page not displayed correctly")

    def _upload_firmware_put(self, path, device_name, uid):
        testfile_path = os.path.join(get_test_data_dir(), path)
        with open(testfile_path, "rb") as fp:
            data = {
                'file': fp,
                'device_name': device_name,
                'device_class': "test_class",
                'firmware_version': "1.0",
                'vendor': "test_vendor",
                'release_date': "2009-01-01",
                'analysis_systems': []
            }
            rv = self.test_client.post('/upload', content_type='multipart/form-data', data=data, follow_redirects=True)
        self.assertIn(b'Upload Successful', rv.data, "upload not successful")
        self.assertIn(uid.encode(), rv.data, "uid not found on upload success page")

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

    def _click_chart(self):
        rv = self.test_client.get('/database/browse?query=%7b%22vendor%22%3A+%7b%22%24eq%22%3A+%22test_vendor%22%7d%7d')
        self.assertIn(self.test_fw_a.uid.encode(), rv.data)

    def _click_release_date_histogram(self):
        rv = self.test_client.get('/database/browse?date="January 2009"')
        self.assertIn(self.test_fw_a.uid.encode(), rv.data)

    def test_show_stats(self):
        self._upload_firmware_get()
        for fw in [self.test_fw_a, self.test_fw_b]:
            self._upload_firmware_put(fw.path, fw.name, fw.uid)
        time.sleep(20)  # wait for analysis to complete

        self.updater.update_all_stats()
        self.updater.shutdown()

        self._show_stats()
        self._click_chart()
        self._click_release_date_histogram()

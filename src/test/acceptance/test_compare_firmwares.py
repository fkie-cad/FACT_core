import os
import time

from test.acceptance.base import TestAcceptanceBase
from helperFunctions.fileSystem import get_test_data_dir


class TestAcceptanceCompareFirmwares(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
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
                'release_date': "01.01.1970",
                'analysis_systems': []
            }
            rv = self.test_client.post('/upload', content_type='multipart/form-data', data=data, follow_redirects=True)
        self.assertIn(b'Upload Successful', rv.data, "upload not successful")
        self.assertIn(uid.encode(), rv.data, "uid not found on upload success page")

    def _show_compare_get(self):
        rv = self.test_client.get('/compare')
        self.assertIn(b'<h2>Compare Firmwares</h2>', rv.data, "start compare page not displayed correctly")

    def _show_compare_post(self):
        data = {
            "uid_list": "418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787;"
                        "d38970f8c5153d1041810d0908292bc8df21e7fd88aab211a8fb96c54afe6b01_319",
            "force": ""
        }
        rv = self.test_client.post('/compare', content_type='multipart/form-data', data=data, follow_redirects=True)
        self.assertIn(b'Your compare task is in progress.', rv.data, "compare wait page not displayed correctly")

    def _show_comparison_results(self):
        rv = self.test_client.get('/compare/{};{}'.format(self.test_fw_a.uid, self.test_fw_b.uid))
        self.assertIn(self.test_fw_a.name.encode(), rv.data, "test firmware a comparison not displayed correctly")
        self.assertIn(self.test_fw_b.name.encode(), rv.data, "test firmware b comparison not displayed correctly")
        self.assertIn(b"File Coverage", rv.data, "comparison page not displayed correctly")

    def _show_home_page(self):
        rv = self.test_client.get('/')
        self.assertIn(b"Latest Comparisons", rv.data, "latest comparisons not displayed on 'home'")

    def test_compare_firmwares(self):
        self._upload_firmware_get()
        for fw in [self.test_fw_a, self.test_fw_b]:
            self._upload_firmware_put(fw.path, fw.name, fw.uid)
        time.sleep(20)  # wait for analysis to complete
        self._show_compare_get()
        self._show_compare_post()
        time.sleep(20)  # wait for comparison to complete
        self._show_comparison_results()
        self._show_home_page()

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
        self._stop_backend()
        super().tearDown()

    def _upload_firmware_get(self):
        rv = self.test_client.get('/upload')
        self.assertIn(b'<h2>Upload Firmware</h2>', rv.data, 'upload page not displayed correctly')

    def _upload_firmware_put(self, path, device_name, uid):
        testfile_path = os.path.join(get_test_data_dir(), path)
        with open(testfile_path, 'rb') as fp:
            data = {
                'file': fp,
                'device_name': device_name,
                'device_class': 'test_class',
                'firmware_version': '1.0',
                'vendor': 'test_vendor',
                'release_date': '01.01.1970',
                'tags': '',
                'analysis_systems': []
            }
            rv = self.test_client.post('/upload', content_type='multipart/form-data', data=data, follow_redirects=True)
        self.assertIn(b'Upload Successful', rv.data, 'upload not successful')
        self.assertIn(uid.encode(), rv.data, 'uid not found on upload success page')

    def _add_firmwares_to_compare(self):
        rv = self.test_client.get('/analysis/{}'.format(self.test_fw_a.uid))
        self.assertIn(self.test_fw_a.uid, rv.data.decode(), '')
        rv = self.test_client.get('/comparison/add/{}'.format(self.test_fw_a.uid), follow_redirects=True)
        self.assertIn('Firmwares Selected for Comparison', rv.data.decode())

        rv = self.test_client.get('/analysis/{}'.format(self.test_fw_b.uid))
        self.assertIn(self.test_fw_b.uid, rv.data.decode())
        self.assertIn(self.test_fw_a.name, rv.data.decode())
        rv = self.test_client.get('/comparison/add/{}'.format(self.test_fw_b.uid), follow_redirects=True)
        self.assertIn('Remove All', rv.data.decode())

    def _start_compare(self):
        rv = self.test_client.get('/compare', follow_redirects=True)
        self.assertIn(b'Your compare task is in progress.', rv.data, 'compare wait page not displayed correctly')

    def _show_comparison_results(self):
        rv = self.test_client.get('/compare/{};{}'.format(self.test_fw_a.uid, self.test_fw_b.uid))
        self.assertIn(self.test_fw_a.name.encode(), rv.data, 'test firmware a comparison not displayed correctly')
        self.assertIn(self.test_fw_b.name.encode(), rv.data, 'test firmware b comparison not displayed correctly')
        self.assertIn(b'File Coverage', rv.data, 'comparison page not displayed correctly')

    def _show_home_page(self):
        rv = self.test_client.get('/')
        self.assertIn(b'Latest Comparisons', rv.data, 'latest comparisons not displayed on "home"')

    def _show_compare_browse(self):
        rv = self.test_client.get('/database/browse_compare')
        self.assertIn(self.test_fw_a.name.encode(), rv.data, 'no compare result shown in browse')

    def test_compare_firmwares(self):
        self._upload_firmware_get()
        for fw in [self.test_fw_a, self.test_fw_b]:
            self._upload_firmware_put(fw.path, fw.name, fw.uid)
        time.sleep(20)  # wait for analysis to complete
        self._add_firmwares_to_compare()
        self._start_compare()
        time.sleep(20)  # wait for comparison to complete
        self._show_comparison_results()
        self._show_home_page()
        self._show_compare_browse()

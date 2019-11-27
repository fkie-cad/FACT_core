import os
import time
from multiprocessing import Event, Value

from storage.db_interface_backend import BackEndDbInterface
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import get_test_data_dir


class TestAcceptanceCompareFirmwares(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self.analysis_finished_event = Event()
        self.compare_finished_event = Event()
        self.elements_finished_analyzing = Value('i', 0)
        self.db_backend_service = BackEndDbInterface(config=self.config)
        self._start_backend(post_analysis=self._analysis_callback, compare_callback=self._compare_callback)
        time.sleep(2)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        self.db_backend_service.shutdown()
        super().tearDown()

    def _analysis_callback(self, fo):
        self.db_backend_service.add_object(fo)
        self.elements_finished_analyzing.value += 1
        if self.elements_finished_analyzing.value == 4 * 2 * 2:  # two firmware container with 3 included files each times two plugins
            self.analysis_finished_event.set()

    def _compare_callback(self):
        self.compare_finished_event.set()

    def _upload_firmware_get(self):
        rv = self.test_client.get('/upload')
        self.assertIn(b'<h2>Upload Firmware</h2>', rv.data, 'upload page not displayed correctly')

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

        rv = self.test_client.get('/analysis/{}'.format(self.test_fw_c.uid))
        self.assertIn(self.test_fw_c.uid, rv.data.decode())
        self.assertIn(self.test_fw_c.name, rv.data.decode())
        rv = self.test_client.get('/comparison/add/{}'.format(self.test_fw_c.uid), follow_redirects=True)
        self.assertIn('Remove All', rv.data.decode())

    def _start_compare(self):
        rv = self.test_client.get('/compare', follow_redirects=True)
        self.assertIn(b'Your compare task is in progress.', rv.data, 'compare wait page not displayed correctly')

    def _show_comparison_results(self):
        rv = self.test_client.get('/compare/{};{}'.format(self.test_fw_a.uid, self.test_fw_c.uid))
        self.assertIn(self.test_fw_a.name.encode(), rv.data, 'test firmware a comparison not displayed correctly')
        self.assertIn(self.test_fw_c.name.encode(), rv.data, 'test firmware b comparison not displayed correctly')
        self.assertIn(b'File Coverage', rv.data, 'comparison page not displayed correctly')

    def _show_home_page(self):
        rv = self.test_client.get('/')
        self.assertIn(b'Latest Comparisons', rv.data, 'latest comparisons not displayed on "home"')

    def _show_compare_browse(self):
        rv = self.test_client.get('/database/browse_compare')
        self.assertIn(self.test_fw_a.name.encode(), rv.data, 'no compare result shown in browse')

    def _show_analysis_without_compare_list(self):
        rv = self.test_client.get('/analysis/{}'.format(self.test_fw_a.uid))
        assert b'Show List of Known Comparisons' not in rv.data

    def _show_analysis_with_compare_list(self):
        rv = self.test_client.get('/analysis/{}'.format(self.test_fw_a.uid))
        assert b'Show List of Known Comparisons' in rv.data

    def test_compare_firmwares(self):
        self._upload_firmware_get()
        for fw in [self.test_fw_a, self.test_fw_c]:
            self._upload_firmware_put(fw.path, fw.name, fw.uid)
        self.analysis_finished_event.wait(timeout=20)
        self._show_analysis_without_compare_list()
        self._add_firmwares_to_compare()
        self._start_compare()
        self.compare_finished_event.wait(timeout=20)
        self._show_comparison_results()
        self._show_home_page()
        self._show_compare_browse()
        self._show_analysis_with_compare_list()

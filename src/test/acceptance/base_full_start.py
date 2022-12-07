import time
from multiprocessing import Event, Value
from pathlib import Path

from storage.db_interface_backend import BackendDbInterface
from test.acceptance.base import TestAcceptanceBase  # pylint: disable=wrong-import-order
from test.common_helper import get_test_data_dir  # pylint: disable=wrong-import-order


class TestAcceptanceBaseFullStart(TestAcceptanceBase):

    NUMBER_OF_FILES_TO_ANALYZE = 4
    NUMBER_OF_PLUGINS = 2

    def setUp(self):
        super().setUp()
        self.analysis_finished_event = Event()
        self.compare_finished_event = Event()
        self.elements_finished_analyzing = Value('i', 0)
        self.db_backend_service = BackendDbInterface()
        self._start_backend(post_analysis=self._analysis_callback, compare_callback=self._compare_callback)
        time.sleep(2)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    def _analysis_callback(self, uid, plugin, analysis_dict):
        self.db_backend_service.add_analysis(uid, plugin, analysis_dict)
        self.elements_finished_analyzing.value += 1
        if self.elements_finished_analyzing.value == self.NUMBER_OF_FILES_TO_ANALYZE * self.NUMBER_OF_PLUGINS:
            self.analysis_finished_event.set()

    def _compare_callback(self):
        self.compare_finished_event.set()

    def upload_test_firmware(self, test_fw):
        testfile_path = Path(get_test_data_dir()) / test_fw.path
        with open(str(testfile_path), 'rb') as fp:
            data = {
                'file': (fp, test_fw.file_name),
                'device_name': test_fw.name,
                'device_part': 'test_part',
                'device_class': 'test_class',
                'version': '1.0',
                'vendor': 'test_vendor',
                'release_date': '1970-01-01',
                'tags': '',
                'analysis_systems': [],
            }
            rv = self.test_client.post('/upload', content_type='multipart/form-data', data=data, follow_redirects=True)
        self.assertIn(b'Upload Successful', rv.data, 'upload not successful')
        self.assertIn(test_fw.uid.encode(), rv.data, 'uid not found on upload success page')

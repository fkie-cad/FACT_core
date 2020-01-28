import time
import tarfile
import io

from test.acceptance.base import TestAcceptanceBase
from test.common_helper import create_test_firmware
from storage.db_interface_backend import BackEndDbInterface


class TestAcceptanceDownloadFile(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend = BackEndDbInterface(config=self.config)
        time.sleep(2)  # wait for systems to start

    def tearDown(self):
        self.db_backend.shutdown()
        self._stop_backend()
        super().tearDown()

    def _show_analysis_page(self, fw):
        rv = self.test_client.get('/analysis/{}'.format(fw.uid))
        self.assertIn(fw.uid.encode(), rv.data)
        self.assertIn(b'test_router', rv.data)
        self.assertIn(b'Router', rv.data)
        self.assertIn(b'test_vendor', rv.data)

    def _start_binary_download(self, fw):
        rv = self.test_client.get('/download/{}'.format(fw.uid))
        self.assertIn(fw.binary, rv.data, 'firmware download unsuccessful')
        self.assertIn('attachment; filename=test.zip', rv.headers['Content-Disposition'])

    def _start_tar_download(self, fw):
        rv = self.test_client.get('/tar-download/{}'.format(fw.uid))
        self.assertNotIn(fw.binary, rv.data, 'tar download yielded original file instead of tar archive')
        tar_file = tarfile.open(fileobj=io.BytesIO(rv.data))
        contents = ', '.join(tar_file.getnames())
        self.assertIn('testfile1', contents, 'test files could not be found in tar download')

    def test_firmware_download(self):
        test_fw = create_test_firmware()
        test_fw.processed_analysis.pop('dummy')
        test_fw.uid = test_fw.uid
        self.db_backend.add_firmware(test_fw)
        self.assertIsNotNone(self.db_backend.firmwares.find_one(test_fw.uid))

        self._show_analysis_page(test_fw)
        self._start_binary_download(test_fw)
        self._start_tar_download(test_fw)

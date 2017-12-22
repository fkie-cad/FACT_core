from base64 import standard_b64encode
from multiprocessing import Queue

from intercom.back_end_binding import InterComBackEndBinding
from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_firmware
from test.integration.intercom import test_backend_scheduler
from test.integration.web_interface.rest.base import RestTestBase


class TestRestDownload(RestTestBase):

    def setUp(self):
        super().setUp()
        self.db_interface = BackEndDbInterface(self.config)
        self.test_queue = Queue()

    def tearDown(self):
        self.test_queue.close()
        self.db_interface.shutdown()
        super().tearDown()

    def test_rest_download_valid(self):
        backend_binding = InterComBackEndBinding(self.config, analysis_service=test_backend_scheduler.AnalysisServiceMock(), compare_service=test_backend_scheduler.ServiceMock(self.test_queue), unpacking_service=test_backend_scheduler.ServiceMock(self.test_queue))

        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_interface.add_firmware(test_firmware)

        try:
            rv = self.test_client.get('/rest/binary/{}'.format(test_firmware.uid), follow_redirects=True)
        finally:
            backend_binding.shutdown()

        assert standard_b64encode(test_firmware.binary) in rv.data
        assert '"file_name": "{}"'.format(test_firmware.file_name).encode() in rv.data
        assert '"SHA256": "{}"'.format(test_firmware.sha256).encode() in rv.data

    def test_rest_download_invalid_uid(self):
        rv = self.test_client.get('/rest/binary/not%20existing%20uid', follow_redirects=True)

        assert b'No firmware with UID not existing uid found in database' in rv.data

    def test_rest_download_invalid_data(self):
        rv = self.test_client.get('/rest/binary/', follow_redirects=True)

        assert b'404 Not Found' in rv.data

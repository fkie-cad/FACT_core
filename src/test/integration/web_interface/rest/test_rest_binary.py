from base64 import standard_b64encode
from multiprocessing import Queue

import pytest

from intercom.back_end_binding import InterComBackEndBinding
from storage.db_interface_backend import BackendDbInterface
from test.common_helper import create_test_firmware, store_binary_on_file_system
from test.integration.intercom import test_backend_scheduler
from test.integration.web_interface.rest.base import RestTestBase


@pytest.mark.usefixtures('database_interfaces')
class TestRestDownload(RestTestBase):
    def setup(self):
        super().setup()
        self.db_interface = BackendDbInterface()
        self.test_queue = Queue()

    def teardown(self):
        self.test_queue.close()

    def test_rest_download_valid(self, backend_config):
        backend_binding = InterComBackEndBinding(
            analysis_service=test_backend_scheduler.AnalysisServiceMock(),
            compare_service=test_backend_scheduler.ServiceMock(self.test_queue),
            unpacking_service=test_backend_scheduler.ServiceMock(self.test_queue),
        )
        backend_binding.start()
        try:
            test_firmware = create_test_firmware(
                device_class='test class', device_name='test device', vendor='test vendor'
            )
            store_binary_on_file_system(backend_config.firmware_file_storage_directory, test_firmware)
            self.db_interface.add_object(test_firmware)

            response = self.test_client.get(f'/rest/binary/{test_firmware.uid}', follow_redirects=True).data.decode()
        finally:
            backend_binding.shutdown()

        assert standard_b64encode(test_firmware.binary).decode() in response
        assert f'"file_name": "{test_firmware.file_name}"' in response
        assert f'"SHA256": "{test_firmware.sha256}"' in response

    def test_rest_download_invalid_uid(self):
        rv = self.test_client.get('/rest/binary/not%20existing%20uid', follow_redirects=True)

        assert b'No firmware with UID not existing uid found in database' in rv.data

    def test_rest_download_invalid_data(self):
        rv = self.test_client.get('/rest/binary/', follow_redirects=True)

        assert b'404 Not Found' in rv.data

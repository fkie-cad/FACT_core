# pylint: disable=no-self-use
from base64 import standard_b64encode
from multiprocessing import Queue

import pytest

from intercom.back_end_binding import InterComBackEndBinding
from storage.db_interface_backend import BackendDbInterface
from test.common_helper import create_test_firmware, store_binary_on_file_system
from test.integration.intercom import test_backend_scheduler


# TODO scope?
@pytest.fixture
def queue():
    q = Queue()
    yield q
    q.close()


@pytest.fixture
def backend_db_interface(cfg_tuple):
    _, configparser_cfg = cfg_tuple
    yield BackendDbInterface(configparser_cfg)


@pytest.mark.usefixtures('use_database')
class TestRestDownload:
    def test_rest_download_valid(self, backend_db_interface, cfg_tuple, queue, test_client):
        cfg, configparser_cfg = cfg_tuple
        backend_binding = InterComBackEndBinding(
            config=configparser_cfg,
            analysis_service=test_backend_scheduler.AnalysisServiceMock(),
            compare_service=test_backend_scheduler.ServiceMock(queue),
            unpacking_service=test_backend_scheduler.ServiceMock(queue)
        )
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        store_binary_on_file_system(cfg.data_storage.firmware_file_storage_directory, test_firmware)
        backend_db_interface.add_object(test_firmware)

        try:
            response = test_client.get(f'/rest/binary/{test_firmware.uid}', follow_redirects=True).data.decode()
        finally:
            backend_binding.shutdown()

        assert standard_b64encode(test_firmware.binary).decode() in response
        assert f'"file_name": "{test_firmware.file_name}"' in response
        assert f'"SHA256": "{test_firmware.sha256}"' in response

    def test_rest_download_invalid_uid(self, test_client):
        rv = test_client.get('/rest/binary/not%20existing%20uid', follow_redirects=True)

        assert b'No firmware with UID not existing uid found in database' in rv.data

    def test_rest_download_invalid_data(self, test_client):
        rv = test_client.get('/rest/binary/', follow_redirects=True)

        assert b'404 Not Found' in rv.data

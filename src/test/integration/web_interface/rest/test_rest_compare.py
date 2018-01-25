import json

from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_firmware
from test.integration.web_interface.rest.base import RestTestBase


class TestRestStartCompare(RestTestBase):

    def setUp(self):
        super().setUp()
        self.db_backend = BackEndDbInterface(config=self.config)

    def tearDown(self):
        self.db_backend.shutdown()
        super().tearDown()

    def test_rest_start_compare_valid(self):
        test_firmware_1 = create_test_firmware(device_class="test class", device_name="test device", vendor="test vendor")
        test_firmware_2 = create_test_firmware(device_class="test class", device_name="test device",
                                               vendor="test vendor", bin_path="container/test.7z")
        self.db_backend.add_firmware(test_firmware_1)
        self.db_backend.add_firmware(test_firmware_2)

        rv = self.test_client.put('/rest/compare', data=json.dumps({"uid_list": [test_firmware_1.uid, test_firmware_2.uid], "redo": True}), follow_redirects=True)
        assert b"Compare started." in rv.data

    def test_rest_start_compare_invalid_uid(self):
        rv = self.test_client.put('/rest/compare', data=json.dumps({"uid_list": ["123", "456"]}), follow_redirects=True)
        assert b"not found in database" in rv.data

    def test_rest_start_compare_invalid_data(self):
        test_firmware = create_test_firmware(device_class="test class", device_name="test device", vendor="test vendor")
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.put('/rest/compare', data=json.dumps({"data": "invalid data"}), follow_redirects=True)
        assert b"Request should be of the form" in rv.data

    def test_rest_get_compare_valid_not_in_db(self):
        test_firmware_1 = create_test_firmware(device_class="test class", device_name="test device", vendor="test vendor")
        test_firmware_2 = create_test_firmware(device_class="test class", device_name="test device",
                                               vendor="test vendor", bin_path="container/test.7z")
        self.db_backend.add_firmware(test_firmware_1)
        self.db_backend.add_firmware(test_firmware_2)

        rv = self.test_client.get('/rest/compare/{};{}'.format(test_firmware_1.uid, test_firmware_2.uid), follow_redirects=True)
        assert b"Compare not found in database." in rv.data

    def test_rest_get_compare_invalid_uid(self):
        rv = self.test_client.get('/rest/compare/123;456', follow_redirects=True)
        assert b"not found in database" in rv.data

    def test_rest_get_compare_invalid_data(self):
        test_firmware = create_test_firmware(device_class="test class", device_name="test device", vendor="test vendor")
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.get('/rest/compare', follow_redirects=True)
        assert b"Compare ID must be of the form" in rv.data

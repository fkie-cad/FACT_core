# pylint: disable=attribute-defined-outside-init,wrong-import-order

from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_firmware
from test.integration.web_interface.rest.base import RestTestBase

TEST_UID = 'deadbeef' * 8 + '_1'


class TestRestStartCompare(RestTestBase):

    def setup(self):
        super().setup()
        self.db_backend = BackEndDbInterface(config=self.config)

    def teardown(self):
        self.db_backend.shutdown()
        super().teardown()

    def test_rest_start_compare_valid(self):
        test_firmware_1 = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        test_firmware_2 = create_test_firmware(device_class='test class', device_name='test device',
                                               vendor='test vendor', bin_path='container/test.7z')
        self.db_backend.add_firmware(test_firmware_1)
        self.db_backend.add_firmware(test_firmware_2)

        data = {'uid_list': [test_firmware_1.uid, test_firmware_2.uid], 'redo': True}
        rv = self.test_client.put('/rest/compare', json=data, follow_redirects=True)
        assert b'Compare started.' in rv.data

    def test_rest_start_compare_invalid_uid(self):
        rv = self.test_client.put('/rest/compare', json={'uid_list': ['123', '456']}, follow_redirects=True)
        assert b'not found in database' in rv.data

    def test_rest_start_compare_invalid_data(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.put('/rest/compare', json={'data': 'invalid data'}, follow_redirects=True)
        assert rv.json['message'] == 'Input payload validation failed'
        assert 'uid_list' in rv.json['errors']
        assert '\'uid_list\' is a required property' in rv.json['errors']['uid_list']

    def test_rest_get_compare_valid_not_in_db(self):
        test_firmware_1 = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        test_firmware_2 = create_test_firmware(device_class='test class', device_name='test device',
                                               vendor='test vendor', bin_path='container/test.7z')
        self.db_backend.add_firmware(test_firmware_1)
        self.db_backend.add_firmware(test_firmware_2)

        rv = self.test_client.get(f'/rest/compare/{test_firmware_1.uid};{test_firmware_2.uid}', follow_redirects=True)
        assert b'Compare not found in database.' in rv.data

    def test_rest_get_compare_invalid_uid(self):
        rv = self.test_client.get(f'/rest/compare/{TEST_UID};{TEST_UID}', follow_redirects=True)
        assert b'not found in database' in rv.data

    def test_rest_get_compare_invalid_data(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.get('/rest/compare', follow_redirects=True)
        assert b'The method is not allowed for the requested URL' in rv.data

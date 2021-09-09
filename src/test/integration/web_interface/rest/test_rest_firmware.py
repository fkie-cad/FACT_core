# pylint: disable=attribute-defined-outside-init,wrong-import-order

import urllib.parse
from base64 import standard_b64encode

import pytest

from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_firmware
from test.integration.web_interface.rest.base import RestTestBase


class TestRestFirmware(RestTestBase):

    def setup(self):
        super().setup()
        self.db_backend = BackEndDbInterface(config=self.config)

    def teardown(self):
        self.db_backend.shutdown()
        super().teardown()

    def test_rest_firmware_existing(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.get('/rest/firmware', follow_redirects=True)
        assert b'uids' in rv.data
        assert b'418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787' in rv.data

    def test_offset_to_empty_response(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.get('/rest/firmware?offset=1', follow_redirects=True)
        assert b'uids' in rv.data
        assert b'418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787' not in rv.data

    def test_stable_response_on_bad_paging(self):
        rv = self.test_client.get('/rest/firmware?offset=Y', follow_redirects=True)
        assert b'error_message' in rv.data
        assert b'Malformed' in rv.data

    def test_rest_search_existing(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        query = urllib.parse.quote('{"device_class": "test class"}')
        rv = self.test_client.get(f'/rest/firmware?query={query}', follow_redirects=True)
        assert b'uids' in rv.data
        assert b'418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787' in rv.data

    def test_rest_search_not_existing(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        query = urllib.parse.quote('{"device_class": "non-existing class"}')
        rv = self.test_client.get(f'/rest/firmware?query={query}', follow_redirects=True)
        assert b'"uids": []' in rv.data

    def test_rest_upload_valid(self):
        data = {
            'binary': standard_b64encode(b'test_file_content').decode(),
            'file_name': 'test_file.txt',
            'device_name': 'test_device',
            'device_part': 'full',
            'device_class': 'test_class',
            'version': '1',
            'vendor': 'test_vendor',
            'release_date': '01.01.1970',
            'tags': '',
            'requested_analysis_systems': ['dummy']
        }
        rv = self.test_client.put('/rest/firmware', json=data, follow_redirects=True)
        assert b'c1f95369a99b765e93c335067e77a7d91af3076d2d3d64aacd04e1e0a810b3ed_17' in rv.data
        assert b'"status": 0' in rv.data

    def test_rest_upload_invalid(self):
        data = {
            'binary': standard_b64encode(b'test_file_content').decode(),
            'file_name': 'test_file.txt',
            'device_name': 'test_device',
            'device_part': 'test_part',
            'device_class': 'test_class',
            'vendor': 'test_vendor',
            'release_date': '01.01.1970',
            'tags': '',
            'requested_analysis_systems': ['dummy']
        }
        rv = self.test_client.put('/rest/firmware', json=data, follow_redirects=True)
        assert rv.json['message'] == 'Input payload validation failed'
        assert 'version' in rv.json['errors']
        assert '\'version\' is a required property' in rv.json['errors']['version']

    def test_rest_download_valid(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.get(f'/rest/firmware/{test_firmware.uid}', follow_redirects=True)

        assert b'file_type' in rv.data
        assert b'test_type' in rv.data
        assert b'unpacker' in rv.data
        assert b'used_unpack_plugin' in rv.data

    def test_rest_download_invalid_uid(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.get('/rest/firmware/invalid%20uid', follow_redirects=True)

        assert b'No firmware with UID invalid uid' in rv.data

    def test_rest_download_invalid_data(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.get('/rest/firmware/', follow_redirects=True)
        assert b'404 Not Found' in rv.data

    @pytest.mark.skip(reason='Intercom not running, thus not a single plugin known')
    def test_rest_update_analysis_success(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        update = urllib.parse.quote('["printable_strings"]')
        rv = self.test_client.put(f'/rest/firmware/{test_firmware.uid}?update={update}', follow_redirects=True)
        assert test_firmware.uid.encode() in rv.data
        assert b'"status": 0' in rv.data

    def test_rest_update_bad_query(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        rv = self.test_client.put(f'/rest/firmware/{test_firmware.uid}?update=not_a_list', follow_redirects=True)
        assert b'"status": 1' in rv.data
        assert b'has to be a list' in rv.data

    def test_rest_download_with_summary(self):
        test_firmware = create_test_firmware(device_class='test class', device_name='test device', vendor='test vendor')
        self.db_backend.add_firmware(test_firmware)

        request_with_summary = self.test_client.get(f'/rest/firmware/{test_firmware.uid}?summary=true', follow_redirects=True)
        assert test_firmware.processed_analysis['dummy']['summary'][0].encode() in request_with_summary.data

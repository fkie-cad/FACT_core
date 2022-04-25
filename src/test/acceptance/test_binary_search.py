# pylint: disable=no-self-use
import pytest

from test.common_helper import upload_test_firmware


@pytest.mark.usefixtures('backend_services')
class TestAcceptanceBinarySearch:
    query = {
        'file': None,
        'textarea': 'rule test_file_string {strings: $a = "This is the second test file" condition: $a }'
    }

    def _query_page_get(self, test_client):
        rv = test_client.get('/database/binary_search')
        assert b'<h3 class="mb-3">Binary Pattern Search</h3>' in rv.data

    def _query_page_post_file_query(self, test_client):
        rv = test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data=self.query,
            follow_redirects=True
        )
        assert b'testfile2' in rv.data

    def _query_page_post_firmware_query(self, test_client, test_fw_a):
        rv = test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={**self.query, 'only_firmware': 'True'},
            follow_redirects=True
        )
        assert test_fw_a.name.encode() in rv.data
        assert b'testfile2' not in rv.data

    def _get_without_request_id(self, test_client):
        rv = test_client.get('/database/binary_search_results')
        assert b'No request ID found' in rv.data

    def test_binary_search(self, test_client, analysis_finished_event, test_fw_a):
        self._query_page_get(test_client)
        upload_test_firmware(test_client, test_fw_a)
        analysis_finished_event.wait(timeout=15)
        self._query_page_post_file_query(test_client)
        self._query_page_post_firmware_query(test_client, test_fw_a)
        self._get_without_request_id(test_client)

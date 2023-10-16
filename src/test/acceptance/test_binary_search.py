import pytest

from test.acceptance.conftest import test_fw_a, upload_test_firmware

query = {
    'file': None,
    'textarea': 'rule test_file_string {strings: $a = "This is the second test file" condition: $a }',
}


class TestAcceptanceBinarySearch:
    def _query_page_get(self, test_client):
        rv = test_client.get('/database/binary_search')
        assert b'<h3 class="mb-3">Binary Pattern Search</h3>' in rv.data

    def _query_page_post_file_query(self, test_client):
        rv = test_client.post(
            '/database/binary_search', content_type='multipart/form-data', data=query, follow_redirects=True
        )
        assert b'testfile2' in rv.data

    def _query_page_post_firmware_query(self, test_client):
        rv = test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={**query, 'only_firmware': 'True'},
            follow_redirects=True,
        )
        assert test_fw_a.name.encode() in rv.data
        assert b'testfile2' not in rv.data

    def _get_without_request_id(self, test_client):
        rv = test_client.get('/database/binary_search_results')
        assert b'No request ID found' in rv.data

    @pytest.mark.SchedulerTestConfig(
        # fmt: off
        # 4 Files and 2 plugins
        items_to_analyze=4 * 2,
    )
    @pytest.mark.usefixtures('intercom_backend_binding')
    def test_binary_search(self, test_client, analysis_finished_event):
        self._query_page_get(test_client)
        upload_test_firmware(test_client, test_fw_a)
        assert analysis_finished_event.wait(timeout=15)
        self._query_page_post_file_query(test_client)
        self._query_page_post_firmware_query(test_client)
        self._get_without_request_id(test_client)

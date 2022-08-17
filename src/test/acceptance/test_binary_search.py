from test.acceptance.base_full_start import TestAcceptanceBaseFullStart


class TestAcceptanceBinarySearch(TestAcceptanceBaseFullStart):

    query = {
        'file': None,
        'textarea': 'rule test_file_string {strings: $a = "This is the second test file" condition: $a }',
    }

    def _query_page_get(self):
        rv = self.test_client.get('/database/binary_search')
        assert b'<h3 class="mb-3">Binary Pattern Search</h3>' in rv.data

    def _query_page_post_file_query(self):
        rv = self.test_client.post(
            '/database/binary_search', content_type='multipart/form-data', data=self.query, follow_redirects=True,
        )
        assert b'testfile2' in rv.data

    def _query_page_post_firmware_query(self):
        rv = self.test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={
                **self.query, 'only_firmware': 'True'
            },
            follow_redirects=True,
        )
        assert self.test_fw_a.name.encode() in rv.data
        assert b'testfile2' not in rv.data

    def _get_without_request_id(self):
        rv = self.test_client.get('/database/binary_search_results')
        assert b'No request ID found' in rv.data

    def test_binary_search(self):
        self._query_page_get()
        self.upload_test_firmware(self.test_fw_a)
        self.analysis_finished_event.wait(timeout=15)
        self._query_page_post_file_query()
        self._query_page_post_firmware_query()
        self._get_without_request_id()

from test.acceptance.base_full_start import TestAcceptanceBaseFullStart


class TestAcceptanceBinarySearch(TestAcceptanceBaseFullStart):

    def _query_page_get(self):
        rv = self.test_client.get('/database/binary_search')
        assert b'<h2>Binary Pattern Search</h2>' in rv.data

    def _query_page_post_file_query(self):
        rv = self.test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={'file': None, 'textarea': 'rule test_file_string {strings: $a = "This is the second test file" condition: $a }'},
            follow_redirects=True
        )
        assert b'testfile2' in rv.data

    def _query_page_post_firmware_query(self):
        rv = self.test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={'file': None, 'textarea': 'rule test_file_string {strings: $a = "This is the second test file" condition: $a }'},
            follow_redirects=True
        )
        assert b'test_device' in rv.data
        assert b'testfile2' not in rv.data

    def test_binary_search(self):
        self._query_page_get()
        self.upload_test_firmware()
        self.analysis_finished_event.wait(timeout=15)
        self._query_page_post_file_query()
        self._query_page_post_firmware_query()

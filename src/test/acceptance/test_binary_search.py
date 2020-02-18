from test.acceptance.base_full_start import TestAcceptanceBaseFullStart


class TestAcceptanceBinarySearch(TestAcceptanceBaseFullStart):

    def _query_page_get(self):
        rv = self.test_client.get('/database/binary_search')
        assert b'<h2>Binary Pattern Search</h2>' in rv.data

    def test_binary_search(self):
        self._query_page_get()
        self.upload_test_firmware()
        self.analysis_finished_event.wait(timeout=15)

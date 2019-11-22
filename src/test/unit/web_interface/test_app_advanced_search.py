from test.common_helper import TEST_TEXT_FILE, TEST_FW_2
from test.unit.web_interface.base import WebInterfaceTest


class TestAppAdvancedSearch(WebInterfaceTest):

    def setUp(self):
        super().setUp()
        self.config['database'] = {}
        self.config['database']['results_per_page'] = "10"

    def test_advanced_search(self):
        rv = self.test_client.post('/database/advanced_search', content_type='multipart/form-data',
                                   data={"advanced_search": "{}"}, follow_redirects=True)
        assert b"test_uid" in rv.data
        assert b"test_fo_uid" not in rv.data

    def test_advanced_search_firmware(self):
        rv = self.test_client.post('/database/advanced_search', content_type='multipart/form-data', follow_redirects=True,
                                   data={"advanced_search": '{{"_id": "{}"}}'.format(TEST_FW_2.uid)})
        assert b"test_uid" in rv.data
        assert b"test_fo_uid" not in rv.data

    def test_advanced_search_file_object(self):
        rv = self.test_client.post('/database/advanced_search', content_type='multipart/form-data', follow_redirects=True,
                                   data={"advanced_search": '{{"_id": "{}"}}'.format(TEST_TEXT_FILE.uid)})
        assert b"test_uid" not in rv.data
        assert b"test_fo_uid" in rv.data

    def test_advanced_search_only_firmwares(self):
        rv = self.test_client.post('/database/advanced_search', content_type='multipart/form-data', follow_redirects=True,
                                   data={"advanced_search": '{{"_id": "{}"}}'.format(TEST_TEXT_FILE.uid), "only_firmwares": "True"})
        assert b"test_uid" in rv.data
        assert b"test_fo_uid" not in rv.data

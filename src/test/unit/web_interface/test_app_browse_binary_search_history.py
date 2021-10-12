from test.unit.web_interface.base import WebInterfaceTest


class TestBrowseBinarySearchHistory(WebInterfaceTest):

    def setUp(self):
        super().setUp()
        self.config['database'] = {}
        self.config['database']['results_per_page'] = '10'

    def test_browse_binary_search_history(self):
        rv = self.test_client.get('/database/browse_binary_search_history')
        print(rv.data.decode())
        assert b'a_ascii_string_rule' in rv.data

from test.unit.web_interface.base import WebInterfaceTest
from io import BytesIO


class TestAppBinarySearch(WebInterfaceTest):

    def test_app_binary_search_get(self):
        rv = self.test_client.get('/database/binary_search')
        assert b'<h2>Binary Search</h2>' in rv.data

    def test_app_binary_search_post_from_file(self):
        rv = self.test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={'file': (BytesIO(b'rule rulename {strings: $a = { 0123456789abcdef } condition: $a }'), 'test_file.txt'), 'textarea': ''},
            follow_redirects=True
        )
        assert b'test firmware' in rv.data
        assert b'Results for signature' in rv.data

    def test_app_binary_search_post_from_textarea(self):
        rv = self.test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={'file': None, 'textarea': 'rule rulename {strings: $a = { 0123456789abcdef } condition: $a }'},
            follow_redirects=True
        )
        assert b'test firmware' in rv.data
        assert b'Results for signature' in rv.data

    def test_app_binary_search_post_invalid_rule(self):
        rv = self.test_client.post('/database/binary_search', content_type='multipart/form-data',
                                   data={'file': (BytesIO(b'invalid_rule'), 'test_file.txt'), 'textarea': ''},
                                   follow_redirects=True)
        assert b'Error in YARA rules' in rv.data

    def test_app_binary_search_post_empty(self):
        rv = self.test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={'file': None, 'textarea': ''},
            follow_redirects=True
        )
        assert b'please select a file or enter rules in the text area' in rv.data

    def test_app_binary_search_post_firmware_not_found(self):
        rv = self.test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={'file': (BytesIO(b'invalid_rule'), 'test_file.txt'), 'textarea': '', 'firmware_uid': 'uid_not_in_db'},
            follow_redirects=True
        )
        assert b'not found in database' in rv.data

    def test_app_binary_search_post_single_firmware(self):
        rv = self.test_client.post(
            '/database/binary_search',
            content_type='multipart/form-data',
            data={'file': None, 'textarea': 'rule rulename {strings: $a = { 0123456789abcdef } condition: $a }', 'firmware_uid': 'uid_in_db'},
            follow_redirects=True
        )
        assert b'test firmware' in rv.data
        assert b'Results for signature' in rv.data

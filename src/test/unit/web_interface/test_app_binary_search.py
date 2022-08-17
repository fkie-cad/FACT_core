# pylint: disable=wrong-import-order
from io import BytesIO

from storage.db_interface_frontend import CachedQuery, MetaEntry
from test.common_helper import CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest

QUERY_CACHE_UID = 'deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567_123'


class DbMock(CommonDatabaseMock):
    @staticmethod
    def generic_search(search_dict: dict, *_, **__):
        if 'test_uid' in str(search_dict) or search_dict == {}:
            return [MetaEntry('test_uid', 'hid', {}, 0)]
        return []

    @staticmethod
    def add_to_search_query_cache(*_, **__):
        return QUERY_CACHE_UID

    @staticmethod
    def get_query_from_cache(query_id):
        if query_id == QUERY_CACHE_UID:
            return CachedQuery(query='{"uid": {"$in": ["test_uid"]}}', yara_rule='some yara rule')
        return None


class TestAppBinarySearch(WebInterfaceTest):
    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)

    def test_app_binary_search_get(self):
        response = self.test_client.get('/database/binary_search').data.decode()
        assert '<h3 class="mb-3">Binary Pattern Search</h3>' in response

    def test_app_binary_search_post_from_file(self):
        response = self._post_binary_search(
            {
                'file':
                (BytesIO(b'rule rulename {strings: $a = { 0123456789abcdef } condition: $a }'), 'test_file.txt'),
                'textarea': '',
            }
        )
        assert 'test_uid' in response

    def test_app_binary_search_post_from_textarea(self):
        response = self._post_binary_search(
            {
                'file': None,
                'textarea': 'rule rulename {strings: $a = { 0123456789abcdef } condition: $a }',
            }
        )
        assert 'test_uid' in response

    def test_app_binary_search_post_invalid_rule(self):
        response = self._post_binary_search({'file': (BytesIO(b'invalid_rule'), 'test_file.txt'), 'textarea': ''})
        assert 'Error in YARA rules' in response

    def test_app_binary_search_post_empty(self):
        response = self._post_binary_search({'file': None, 'textarea': ''})
        assert 'please select a file or enter rules in the text area' in response

    def test_app_binary_search_post_firmware_not_found(self):
        response = self._post_binary_search(
            {
                'file': (BytesIO(b'invalid_rule'), 'test_file.txt'),
                'textarea': '',
                'firmware_uid': 'uid_not_in_db',
            }
        )
        assert 'not found in database' in response

    def test_app_binary_search_post_single_firmware(self):
        response = self._post_binary_search(
            {
                'file': None,
                'firmware_uid': 'uid_in_db',
                'textarea': 'rule rulename {strings: $a = { 0123456789abcdef } condition: $a }',
            }
        )
        assert 'test_uid' in response

    def _post_binary_search(self, query: dict) -> str:
        response = self.test_client.post(
            '/database/binary_search', content_type='multipart/form-data', data=query, follow_redirects=True
        )
        return response.data.decode()

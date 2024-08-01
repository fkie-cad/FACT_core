from io import BytesIO

import pytest

from fact.storage.db_interface_frontend import CachedQuery, MetaEntry
from tests.common_helper import CommonDatabaseMock

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


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
class TestAppBinarySearch:
    def test_app_binary_search_get(self, test_client):
        response = test_client.get('/database/binary_search').data.decode()
        assert '<h3 class="mb-3">Binary Pattern Search</h3>' in response

    def test_app_binary_search_post_from_file(self, test_client):
        response = _post_binary_search(
            test_client,
            {
                'file': (
                    BytesIO(b'rule rulename {strings: $a = { 0123456789abcdef } condition: $a }'),
                    'test_file.txt',
                ),
                'textarea': '',
            },
        )
        assert 'test_uid' in response

    def test_app_binary_search_post_from_textarea(self, test_client):
        response = _post_binary_search(
            test_client, {'file': None, 'textarea': 'rule rulename {strings: $a = { 0123456789abcdef } condition: $a }'}
        )
        assert 'test_uid' in response

    def test_app_binary_search_post_invalid_rule(self, test_client):
        response = _post_binary_search(
            test_client, {'file': (BytesIO(b'invalid_rule'), 'test_file.txt'), 'textarea': ''}
        )
        assert 'Error in YARA rules' in response

    def test_app_binary_search_post_empty(self, test_client):
        response = _post_binary_search(test_client, {'file': None, 'textarea': ''})
        assert 'please select a file or enter rules in the text area' in response

    def test_app_binary_search_post_firmware_not_found(self, test_client):
        response = _post_binary_search(
            test_client,
            {'file': (BytesIO(b'invalid_rule'), 'test_file.txt'), 'textarea': '', 'firmware_uid': 'uid_not_in_db'},
        )
        assert 'not found in database' in response

    def test_app_binary_search_post_single_firmware(self, test_client):
        response = _post_binary_search(
            test_client,
            {
                'file': None,
                'firmware_uid': 'uid_in_db',
                'textarea': 'rule rulename {strings: $a = { 0123456789abcdef } condition: $a }',
            },
        )
        assert 'test_uid' in response


def _post_binary_search(test_client, query: dict) -> str:
    response = test_client.post(
        '/database/binary_search', content_type='multipart/form-data', data=query, follow_redirects=True
    )
    return response.data.decode()

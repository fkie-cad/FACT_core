from urllib.parse import quote

from test.common_helper import TEST_TEXT_FILE, CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest


class DbMock(CommonDatabaseMock):
    @staticmethod
    def rest_get_file_object_uids(**_):
        return []


class TestRestFileObject(WebInterfaceTest):
    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)

    def test_empty_uid(self):
        result = self.test_client.get('/rest/file_object/').data
        assert b'404 Not Found' in result

    def test_get_all_objects(self):
        result = self.test_client.get('/rest/file_object').json
        assert 'error_message' not in result

    def test_paging(self):
        result = self.test_client.get('/rest/file_object?offset=1').json
        assert 'error_message' not in result
        assert not result['uids']

    def test_bad_query(self):
        bad_json_document = '{"parameter": False}'
        result = self.test_client.get(f'/rest/file_object?query={quote(bad_json_document)}').json
        assert 'error_message' in result
        assert 'Query must be a json' in result['error_message']

    def test_non_existing_uid(self):
        response = self.test_client.get('/rest/file_object/some_uid').json
        assert 'No file object with UID some_uid' in response['error_message']

    def test_successful_request(self):
        result = self.test_client.get(f'/rest/file_object/{TEST_TEXT_FILE.uid}').json
        assert 'file_object' in result
        assert all(section in result['file_object'] for section in ['meta_data', 'analysis'])
        assert isinstance(result['file_object']['meta_data']['virtual_file_path'], dict)

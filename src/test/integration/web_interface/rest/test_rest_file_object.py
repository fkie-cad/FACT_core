import pytest

from test.common_helper import create_test_file_object
from test.integration.web_interface.rest.base import RestTestBase


@pytest.mark.usefixtures('database_interfaces')
class TestRestFileObject(RestTestBase):
    def test_rest_download_valid(self, backend_db):
        test_file_object = create_test_file_object()
        backend_db.add_object(test_file_object)

        rv = self.test_client.get(f'/rest/file_object/{test_file_object.uid}', follow_redirects=True)

        assert b'hid' in rv.data
        assert b'size' in rv.data

    def test_rest_request_multiple_file_objects(self):
        rv = self.test_client.get('/rest/file_object', follow_redirects=True)

        assert b'uids' in rv.data
        assert b'status:" 1' not in rv.data

    def test_rest_download_invalid_uid(self):
        rv = self.test_client.get('/rest/file_object/invalid%20uid', follow_redirects=True)

        assert b'No file object with UID invalid uid' in rv.data

    def test_rest_download_invalid_data(self):
        rv = self.test_client.get('/rest/file_object/', follow_redirects=True)
        assert b'404 Not Found' in rv.data

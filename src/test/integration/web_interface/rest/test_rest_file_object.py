from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_file_object
from test.integration.web_interface.rest.base import RestTestBase


class TestRestFileObject(RestTestBase):

    def setUp(self):
        super().setUp()
        self.db_backend = BackEndDbInterface(config=self.config)

    def tearDown(self):
        self.db_backend.shutdown()
        super().tearDown()

    def test_rest_download_valid(self):
        test_file_object = create_test_file_object()
        self.db_backend.add_file_object(test_file_object)

        rv = self.test_client.get('/rest/file_object/{}'.format(test_file_object.uid), follow_redirects=True)

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

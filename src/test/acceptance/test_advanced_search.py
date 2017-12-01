import json
from urllib.parse import quote

from storage.db_interface_backend import BackEndDbInterface
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import create_test_firmware, create_test_file_object


class TestAcceptanceAdvancedSearch(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self.db_backend_interface = BackEndDbInterface(self.config)
        self.config['database'] = {}
        self.config['database']['results_per_page'] = '10'
        self.parent_fw = create_test_firmware()
        self.child_fo = create_test_file_object()
        uid = self.parent_fw.get_uid()
        self.child_fo.virtual_file_path = {uid: ['|{}|/folder/{}'.format(uid, self.child_fo.file_name)]}
        self.db_backend_interface.add_object(self.parent_fw)
        self.child_fo.processed_analysis['unpacker'] = {}
        self.child_fo.processed_analysis['unpacker']['plugin_used'] = 'test'
        self.child_fo.processed_analysis['file_type']['mime'] = "some_type"
        self.db_backend_interface.add_object(self.child_fo)

    def tearDown(self):
        super().tearDown()
        self.db_backend_interface.shutdown()

    def test_advanced_search_get(self):
        rv = self.test_client.get('/database/advanced_search')
        assert b'<h2>Advanced Search</h2>' in rv.data

    def test_advanced_search(self):
        rv = self.test_client.post('/database/advanced_search', content_type='multipart/form-data',
                                   data={'advanced_search': '{}'}, follow_redirects=True)
        assert b'Please enter a valid search request' not in rv.data
        assert self.parent_fw.get_uid().encode() in rv.data
        assert self.child_fo.get_uid().encode() not in rv.data

    def test_advanced_search_file_object(self):
        rv = self.test_client.post('/database/advanced_search', content_type='multipart/form-data',
                                   data={'advanced_search': json.dumps({'_id': self.child_fo.get_uid()})}, follow_redirects=True)
        assert b'Please enter a valid search request' not in rv.data
        assert b'<strong>UID:</strong> ' + self.parent_fw.get_uid().encode() not in rv.data
        assert b'<strong>UID:</strong> ' + self.child_fo.get_uid().encode() in rv.data

    def test_advanced_search_only_firmwares(self):
        rv = self.test_client.post('/database/advanced_search', content_type='multipart/form-data',
                                   data={'advanced_search': json.dumps({'_id': self.child_fo.get_uid()}), 'only_firmwares': 'True'}, follow_redirects=True)
        assert b'Please enter a valid search request' not in rv.data
        assert self.child_fo.get_uid().encode() not in rv.data
        assert self.parent_fw.get_uid().encode() in rv.data

    def test_rest_recursive_firmware_search(self):
        query = quote(json.dumps({'file_name': self.child_fo.file_name}))
        response = self.test_client.get('/rest/firmware?recursive=true&query={}'.format(query)).data
        assert b'error_message' not in response
        assert self.parent_fw.uid.encode() in response

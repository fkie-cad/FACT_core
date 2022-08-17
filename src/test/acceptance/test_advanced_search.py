import json
from urllib.parse import quote

from storage.db_interface_backend import BackendDbInterface
from test.acceptance.base import TestAcceptanceBase  # pylint: disable=wrong-import-order
from test.common_helper import (  # pylint: disable=wrong-import-order
    create_test_file_object, create_test_firmware, generate_analysis_entry
)


class TestAcceptanceAdvancedSearch(TestAcceptanceBase):
    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend_interface = BackendDbInterface(self.config)

        self.parent_fw = create_test_firmware()
        self.child_fo = create_test_file_object()
        uid = self.parent_fw.uid
        self.child_fo.parent_firmware_uids = [uid]
        self.db_backend_interface.add_object(self.parent_fw)
        self.child_fo.processed_analysis['unpacker'] = generate_analysis_entry(analysis_result={'plugin_used': 'test'})
        self.child_fo.processed_analysis['file_type'] = generate_analysis_entry(analysis_result={'mime': 'some_type'})
        self.db_backend_interface.add_object(self.child_fo)
        self.other_fw = create_test_firmware()
        self.other_fw.uid = '1234abcd_123'
        self.db_backend_interface.add_object(self.other_fw)

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    def test_advanced_search_get(self):
        rv = self.test_client.get('/database/advanced_search')
        assert b'<h3 class="mb-3">Advanced Search</h3>' in rv.data

    def test_advanced_search(self):
        rv = self.test_client.post(
            '/database/advanced_search',
            content_type='multipart/form-data',
            data={'advanced_search': '{}'},
            follow_redirects=True
        )
        assert b'Please enter a valid search request' not in rv.data
        assert self.parent_fw.uid.encode() in rv.data
        assert self.child_fo.uid.encode() not in rv.data

    def test_advanced_search_file_object(self):
        rv = self.test_client.post(
            '/database/advanced_search',
            content_type='multipart/form-data',
            data={'advanced_search': json.dumps({'uid': self.child_fo.uid})},
            follow_redirects=True
        )
        assert b'Please enter a valid search request' not in rv.data
        assert b'<strong>UID:</strong> ' + self.parent_fw.uid.encode() not in rv.data
        assert b'<strong>UID:</strong> ' + self.child_fo.uid.encode() in rv.data

    def test_advanced_search_only_firmwares(self):
        query = {'advanced_search': json.dumps({'uid': self.child_fo.uid}), 'only_firmwares': 'True'}
        response = self.test_client.post(
            '/database/advanced_search', content_type='multipart/form-data', data=query, follow_redirects=True
        ).data.decode()
        assert 'Please enter a valid search request' not in response
        assert self.child_fo.uid not in response
        assert self.parent_fw.uid in response

    def test_advanced_search_inverse_only_firmware(self):
        query = {
            'advanced_search': json.dumps({'uid': self.child_fo.uid}), 'only_firmwares': 'True', 'inverted': 'True'
        }
        response = self.test_client.post(
            '/database/advanced_search', content_type='multipart/form-data', follow_redirects=True, data=query
        ).data.decode()
        assert 'Please enter a valid search request' not in response
        assert self.child_fo.uid not in response
        assert f'<strong>UID:</strong> {self.parent_fw.uid}' not in response
        assert f'<strong>UID:</strong> {self.other_fw.uid}' in response

    def test_rest_recursive_firmware_search(self):
        query = quote(json.dumps({'file_name': self.child_fo.file_name}))
        response = self.test_client.get(f'/rest/firmware?recursive=true&query={query}').data
        assert b'error_message' not in response
        assert self.parent_fw.uid.encode() in response

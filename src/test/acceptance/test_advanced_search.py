# pylint: disable=no-self-use
import json
from urllib.parse import quote

import pytest

from test.common_helper import (  # pylint: disable=wrong-import-order
    create_test_file_object, create_test_firmware, generate_analysis_entry
)

parent_fw = create_test_firmware()
child_fo = create_test_file_object()
uid = parent_fw.uid

child_fo.parent_firmware_uids = [uid]
child_fo.processed_analysis['unpacker'] = generate_analysis_entry(analysis_result={'plugin_used': 'test'})
child_fo.processed_analysis['file_type'] = generate_analysis_entry(analysis_result={'mime': 'some_type'})

other_fw = create_test_firmware()
other_fw.uid = '1234abcd_123'


@pytest.fixture
def initialize_with_stub_firmware(backend_services):
    db_backend_interface = backend_services.db_backend_interface

    db_backend_interface.add_object(child_fo)
    db_backend_interface.add_object(other_fw)
    db_backend_interface.add_object(parent_fw)


@pytest.mark.usefixtures('initialize_with_stub_firmware')
class TestAcceptanceAdvancedSearch:
    def test_advanced_search_get(self, test_client):
        rv = test_client.get('/database/advanced_search')
        assert b'<h3 class="mb-3">Advanced Search</h3>' in rv.data

    def test_advanced_search(self, test_client):
        rv = test_client.post(
            '/database/advanced_search',
            content_type='multipart/form-data',
            data={'advanced_search': '{}'},
            follow_redirects=True
        )
        assert b'Please enter a valid search request' not in rv.data
        assert parent_fw.uid.encode() in rv.data
        assert child_fo.uid.encode() not in rv.data

    def test_advanced_search_file_object(self, test_client):
        rv = test_client.post(
            '/database/advanced_search',
            content_type='multipart/form-data',
            data={'advanced_search': json.dumps({'uid': child_fo.uid})},
            follow_redirects=True
        )
        assert b'Please enter a valid search request' not in rv.data
        assert b'<strong>UID:</strong> ' + parent_fw.uid.encode() not in rv.data
        assert b'<strong>UID:</strong> ' + child_fo.uid.encode() in rv.data

    def test_advanced_search_only_firmwares(self, test_client):
        query = {'advanced_search': json.dumps({'uid': child_fo.uid}), 'only_firmwares': 'True'}
        response = test_client.post('/database/advanced_search', content_type='multipart/form-data', data=query, follow_redirects=True).data.decode()
        assert 'Please enter a valid search request' not in response
        assert child_fo.uid not in response
        assert parent_fw.uid in response

    def test_advanced_search_inverse_only_firmware(self, test_client):
        query = {'advanced_search': json.dumps({'uid': child_fo.uid}), 'only_firmwares': 'True', 'inverted': 'True'}
        response = test_client.post('/database/advanced_search', content_type='multipart/form-data', follow_redirects=True, data=query).data.decode()
        assert 'Please enter a valid search request' not in response

    def test_rest_recursive_firmware_search(self, test_client):
        # TODO
        query = quote(json.dumps({'file_name': child_fo.file_name}))
        response = test_client.get(f'/rest/firmware?recursive=true&query={query}').data
        assert child_fo.uid not in response
        assert f'<strong>UID:</strong> {self.parent_fw.uid}' not in response
        assert f'<strong>UID:</strong> {self.other_fw.uid}' in response

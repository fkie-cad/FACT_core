from __future__ import annotations

import json
from urllib.parse import quote

import pytest

from test.common_helper import (
    assert_search_result,
    create_test_file_object,
    create_test_firmware,
    generate_analysis_entry,
)

parent_fw = create_test_firmware()
child_fo = create_test_file_object()
other_fw = create_test_firmware()
other_fw.uid = '1234abcd_123'


@pytest.fixture(autouse=True)
def _auto_insert_firmwares(backend_db):
    uid = parent_fw.uid
    child_fo.parent_firmware_uids = [uid]
    child_fo.virtual_file_path = {parent_fw.uid: ['/some/path']}
    child_fo.parent_firmware_uids = [parent_fw.uid]
    child_fo.processed_analysis['unpacker'] = generate_analysis_entry(analysis_result={'plugin_used': 'test'})
    child_fo.processed_analysis['file_type'] = generate_analysis_entry(analysis_result={'mime': 'some_type'})
    backend_db.insert_multiple_objects(parent_fw, child_fo, other_fw)


class TestAcceptanceAdvancedSearch:
    def test_advanced_search_get(self, test_client):
        rv = test_client.get('/database/advanced_search')
        assert b'<h3 class="mb-3">Advanced Search</h3>' in rv.data

    def test_advanced_search(self, test_client):
        response = test_client.post(
            '/database/advanced_search',
            content_type='multipart/form-data',
            data={'advanced_search': '{}'},
            follow_redirects=True,
        )
        assert_search_result(response, included=[parent_fw], excluded=[child_fo])

    @pytest.mark.usefixtures('intercom_backend_binding')
    def test_advanced_search_file_object(self, test_client):
        response = test_client.post(
            '/database/advanced_search',
            content_type='multipart/form-data',
            data={'advanced_search': json.dumps({'uid': child_fo.uid})},
            follow_redirects=True,
        )
        assert_search_result(response, included=[child_fo], excluded=[parent_fw])

    def test_advanced_search_only_firmwares(self, test_client):
        response = test_client.post(
            '/database/advanced_search',
            content_type='multipart/form-data',
            data={'advanced_search': json.dumps({'uid': child_fo.uid}), 'only_firmwares': 'True'},
            follow_redirects=True,
        )
        assert_search_result(response, included=[parent_fw], excluded=[child_fo])

    def test_advanced_search_inverse_only_firmware(self, test_client):
        query = {
            'advanced_search': json.dumps({'uid': child_fo.uid}),
            'only_firmwares': 'True',
            'inverted': 'True',
        }
        response = test_client.post(
            '/database/advanced_search', content_type='multipart/form-data', follow_redirects=True, data=query
        )
        assert_search_result(response, included=[other_fw], excluded=[child_fo, parent_fw])

    def test_rest_recursive_firmware_search(self, test_client):
        query = quote(json.dumps({'file_name': child_fo.file_name}))
        response = test_client.get(f'/rest/firmware?recursive=true&query={query}').data
        assert b'error_message' not in response
        assert parent_fw.uid.encode() in response

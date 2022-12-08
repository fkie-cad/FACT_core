import json
from urllib.parse import quote
import pytest

from test.common_helper import (  # pylint: disable=wrong-import-order
    create_test_file_object,
    create_test_firmware,
    generate_analysis_entry,
)

parent_fw = create_test_firmware()
child_fo = create_test_file_object()
other_fw = create_test_firmware()


# TODO: These tests are kind of badly written.
#       They work even if the intercom_backend_binding thing is not started
@pytest.fixture(autouse=True)
def _autouse_intercom_backend_binding(intercom_backend_binding):
    pass


@pytest.fixture(autouse=True)
def _auto_insert_firmwares(backend_db):
    uid = parent_fw.uid
    child_fo.parent_firmware_uids = [uid]
    backend_db.add_object(parent_fw)
    child_fo.processed_analysis['unpacker'] = generate_analysis_entry(analysis_result={'plugin_used': 'test'})
    child_fo.processed_analysis['file_type'] = generate_analysis_entry(analysis_result={'mime': 'some_type'})
    backend_db.add_object(child_fo)

    other_fw = create_test_firmware()
    other_fw.uid = '1234abcd_123'
    backend_db.add_object(other_fw)


def test_advanced_search_get(test_client):
    rv = test_client.get('/database/advanced_search')
    assert b'<h3 class="mb-3">Advanced Search</h3>' in rv.data


def test_advanced_search(test_client):
    rv = test_client.post(
        '/database/advanced_search',
        content_type='multipart/form-data',
        data={'advanced_search': '{}'},
        follow_redirects=True,
    )
    assert b'Please enter a valid search request' not in rv.data
    assert parent_fw.uid.encode() in rv.data
    assert child_fo.uid.encode() not in rv.data


def test_advanced_search_file_object(test_client):
    rv = test_client.post(
        '/database/advanced_search',
        content_type='multipart/form-data',
        data={'advanced_search': json.dumps({'uid': child_fo.uid})},
        follow_redirects=True,
    )
    assert b'Please enter a valid search request' not in rv.data
    assert b'<strong>UID:</strong> ' + parent_fw.uid.encode() not in rv.data
    assert b'<strong>UID:</strong> ' + child_fo.uid.encode() in rv.data


def test_advanced_search_only_firmwares(test_client):
    query = {'advanced_search': json.dumps({'uid': child_fo.uid}), 'only_firmwares': 'True'}
    response = test_client.post(
        '/database/advanced_search', content_type='multipart/form-data', data=query, follow_redirects=True
    ).data.decode()
    assert 'Please enter a valid search request' not in response
    assert child_fo.uid not in response
    assert parent_fw.uid in response


@pytest.mark.skip(reason="TODO this does not work")
def test_advanced_search_inverse_only_firmware(test_client):
    query = {
        'advanced_search': json.dumps({'uid': child_fo.uid}),
        'only_firmwares': 'True',
        'inverted': 'True',
    }
    response = test_client.post(
        '/database/advanced_search', content_type='multipart/form-data', follow_redirects=True, data=query
    ).data.decode()
    assert 'Please enter a valid search request' not in response
    assert child_fo.uid not in response
    assert f'<strong>UID:</strong> {parent_fw.uid}' not in response
    assert f'<strong>UID:</strong> {other_fw.uid}' in response


def test_rest_recursive_firmware_search(test_client):
    query = quote(json.dumps({'file_name': child_fo.file_name}))
    response = test_client.get(f'/rest/firmware?recursive=true&query={query}').data
    assert b'error_message' not in response
    assert parent_fw.uid.encode() in response

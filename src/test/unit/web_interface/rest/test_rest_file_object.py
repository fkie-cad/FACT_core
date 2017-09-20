from urllib.parse import quote

from test.common_helper import TEST_TEXT_FILE
from .conftest import decode_response


def test_empty_uid(test_app):
    result = test_app.get('/rest/file_object/').data
    assert b'404 Not Found' in result


def test_get_all_objects(test_app):
    result = decode_response(test_app.get('/rest/file_object'))
    assert 'error_message' not in result


def test_paging(test_app):
    result = decode_response(test_app.get('/rest/file_object?offset=1'))
    assert 'error_message' not in result
    assert not result['uids']


def test_bad_query(test_app):
    bad_json_document = '{"parameter": False}'
    result = decode_response(test_app.get('/rest/file_object?query={}'.format(quote(bad_json_document))))
    assert 'error_message' in result
    assert 'Query must be a json' in result['error_message']


def test_non_existing_uid(test_app):
    response = decode_response(test_app.get('/rest/file_object/some_uid'))
    assert 'No file object with UID some_uid' in response['error_message']


def test_successful_request(test_app):
    result = decode_response(test_app.get('/rest/file_object/{}'.format(TEST_TEXT_FILE.uid)))
    assert 'file_object' in result
    assert all(section in result['file_object'] for section in ['meta_data', 'analysis'])

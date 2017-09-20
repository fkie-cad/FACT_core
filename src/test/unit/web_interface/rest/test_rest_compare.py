import json

from test.common_helper import TEST_FW, TEST_TEXT_FILE
from .conftest import decode_response


def test_bad_request(test_app):
    result = decode_response(test_app.put('/rest/compare'))
    assert 'Request should be a dict' in result['error_message']

    result = test_app.get('/rest/compare/').data
    assert b'404 Not Found' in result


def test_empty_data(test_app):
    result = decode_response(test_app.put('/rest/compare', data=json.dumps(dict())))
    assert 'Request should be of the form' in result['error_message']

    result = decode_response(test_app.get('/rest/compare'))
    assert 'Compare ID must be of the form' in result['error_message']


def test_get_unknown_compare(test_app):
    compare_id = 'someid_size;anotherid_size'
    result = decode_response(test_app.get('/rest/compare/{}'.format(compare_id)))
    assert 'Compare not found in database' in result['error_message']


def test_get_success(test_app):
    compare_id = '{};{}'.format(TEST_FW.uid, TEST_TEXT_FILE.uid)
    result = decode_response(test_app.get('/rest/compare/{}'.format(compare_id)))
    assert 'this_is' in result
    assert result['this_is'] == 'a_compare_result'


def test_put_unknown_objects(test_app):
    data = {'uid_list': ['someid_size', 'anotherid_size']}
    result = decode_response(test_app.put('/rest/compare', data=json.dumps(data)))
    assert result['status'] == 1
    assert result['error_message'] == 'bla'


def test_put_pre_existing(test_app):
    data = {'uid_list': [TEST_FW.uid, TEST_TEXT_FILE.uid], 'redo': False}
    result = decode_response(test_app.put('/rest/compare', data=json.dumps(data)))
    assert result['status'] == 1
    assert 'Compare already exists' in result['error_message']


def test_put_success(test_app):
    data = {'uid_list': [TEST_FW.uid, TEST_TEXT_FILE.uid], 'redo': True}
    result = decode_response(test_app.put('/rest/compare', data=json.dumps(data)))
    assert result['status'] == 0
    assert 'Compare started' in result['message']

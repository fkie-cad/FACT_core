from test.common_helper import TEST_FW, TEST_TEXT_FILE

from .conftest import decode_response

UID_1 = 'deadbeef' * 8 + '_1'
UID_2 = 'decafbad' * 8 + '_2'


def test_bad_request(test_app):
    result = decode_response(test_app.put('/rest/compare'))
    assert 'Input payload validation failed' in result['message']

    result = test_app.get('/rest/compare/').data
    assert b'404 Not Found' in result


def test_empty_data(test_app):
    result = decode_response(test_app.put('/rest/compare', json={}))
    assert 'Input payload validation failed' in result['message']

    result = decode_response(test_app.get('/rest/compare'))
    assert 'The method is not allowed for the requested URL' in result['message']


def test_get_unknown_compare(test_app):
    compare_id = f'{UID_1};{UID_2}'
    result = decode_response(test_app.get(f'/rest/compare/{compare_id}'))
    assert 'Compare not found in database' in result['error_message']


def test_get_invalid_compare_id(test_app):
    compare_id = f'invalid_uid;{UID_2}'
    result = decode_response(test_app.get(f'/rest/compare/{compare_id}'))
    assert 'contains invalid chars' in result['error_message']


def test_get_invalid_compare_id_2(test_app):
    compare_id = f'deadbeef_1;{UID_2}'
    result = decode_response(test_app.get(f'/rest/compare/{compare_id}'))
    assert 'contains invalid UIDs' in result['error_message']


def test_get_success(test_app):
    compare_id = '{};{}'.format(TEST_FW.uid, TEST_TEXT_FILE.uid)
    result = decode_response(test_app.get(f'/rest/compare/{compare_id}'))
    assert 'this_is' in result
    assert result['this_is'] == 'a_compare_result'


def test_put_unknown_objects(test_app):
    data = {'uid_list': [UID_1, UID_2]}
    result = decode_response(test_app.put('/rest/compare', json=data))
    assert result['error_message'] == 'bla'
    assert result['status'] == 1


def test_put_pre_existing(test_app):
    data = {'uid_list': [TEST_FW.uid, TEST_TEXT_FILE.uid], 'redo': False}
    result = decode_response(test_app.put('/rest/compare', json=data))
    assert result['status'] == 1
    assert 'Compare already exists' in result['error_message']


def test_put_success(test_app):
    data = {'uid_list': [TEST_FW.uid, TEST_TEXT_FILE.uid], 'redo': True}
    result = decode_response(test_app.put('/rest/compare', json=data))
    assert result['status'] == 0
    assert 'Compare started' in result['message']

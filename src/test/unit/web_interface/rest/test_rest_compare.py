from test.common_helper import COMPARISON_ID, TEST_FW, TEST_FW_2

UID_1 = 'deadbeef' * 8 + '_1'
UID_2 = 'decafbad' * 8 + '_2'


def test_bad_request(test_client):
    response = test_client.put('/rest/compare')
    assert response.status_code == 400


def test_empty_data(test_client):
    result = test_client.put('/rest/compare', json={}).json
    assert 'Input payload validation failed' in result['message']

    result = test_client.get('/rest/compare').json
    assert 'The method is not allowed for the requested URL' in result['message']


def test_get_unknown_compare(test_client):
    compare_id = f'{UID_1};{UID_2}'
    result = test_client.get(f'/rest/compare/{compare_id}').json
    assert 'Compare not found in database' in result['error_message']


def test_get_invalid_compare_id(test_client):
    compare_id = f'invalid_uid;{UID_2}'
    result = test_client.get(f'/rest/compare/{compare_id}').json
    assert 'contains invalid chars' in result['error_message']


def test_get_invalid_compare_id_2(test_client):
    compare_id = f'deadbeef_1;{UID_2}'
    result = test_client.get(f'/rest/compare/{compare_id}').json
    assert 'contains invalid UIDs' in result['error_message']


def test_get_success(test_client):
    result = test_client.get(f'/rest/compare/{COMPARISON_ID}').json
    assert 'general' in result
    assert 'hid' in result['general']


def test_put_unknown_objects(test_client):
    data = {'uid_list': [UID_1, UID_2]}
    result = test_client.put('/rest/compare', json=data).json
    assert 'Some objects are not found in the database' in result['error_message']
    assert result['status'] == 1


def test_put_pre_existing(test_client):
    data = {'uid_list': [TEST_FW.uid, TEST_FW_2.uid], 'redo': False}
    result = test_client.put('/rest/compare', json=data).json
    assert result['status'] == 1
    assert 'Compare already exists' in result['error_message']


def test_put_success(test_client):
    data = {'uid_list': [TEST_FW.uid, TEST_FW_2.uid], 'redo': True}
    result = test_client.put('/rest/compare', json=data).json
    assert result['status'] == 0
    assert 'Compare started' in result['message']

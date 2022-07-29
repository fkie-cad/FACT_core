YARA_TEST_RULE = 'rule rulename {strings: $a = "foobar" condition: $a}'


def test_no_data(test_client):
    response = test_client.post('/rest/binary_search')
    assert response.status_code == 400


def test_no_rule_file(test_client):
    result = test_client.post('/rest/binary_search', json={}).json
    assert 'Input payload validation failed' in result['message']
    assert 'errors' in result
    assert '\'rule_file\' is a required property' in result['errors']['rule_file']


def test_wrong_rule_file_format(test_client):
    result = test_client.post('/rest/binary_search', json={'rule_file': 'not an actual rule file'}).json
    assert 'Error in YARA rule file' in result['error_message']


def test_firmware_uid_not_found(test_client):
    data = {'rule_file': YARA_TEST_RULE, 'uid': 'not found'}
    result = test_client.post('/rest/binary_search', json=data).json
    assert 'not found in database' in result['error_message']


def test_start_binary_search(test_client):
    result = test_client.post('/rest/binary_search', json={'rule_file': YARA_TEST_RULE}).json
    assert 'Started binary search' in result['message']


def test_start_binary_search_with_uid(test_client):
    data = {'rule_file': YARA_TEST_RULE, 'uid': 'uid_in_db'}
    result = test_client.post('/rest/binary_search', json=data).json
    assert 'Started binary search' in result['message']


def test_get_result_without_search_id(test_client):
    result = test_client.get('/rest/binary_search').json
    assert 'The method is not allowed for the requested URL' in result['message']


def test_get_result_non_existent_id(test_client):
    result = test_client.get('/rest/binary_search/foobar').json
    assert 'result is not ready yet' in result['error_message']

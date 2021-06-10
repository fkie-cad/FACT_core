from .conftest import decode_response

YARA_TEST_RULE = 'rule rulename {strings: $a = "foobar" condition: $a}'


def test_no_data(test_app):
    result = decode_response(test_app.post('/rest/binary_search'))
    assert 'Input payload validation failed' in result['message']
    assert 'errors' in result
    assert 'is a required property' in result['errors']['rule_file']


def test_no_rule_file(test_app):
    result = decode_response(test_app.post('/rest/binary_search', json=dict()))
    assert 'Input payload validation failed' in result['message']
    assert 'errors' in result
    assert '\'rule_file\' is a required property' in result['errors']['rule_file']


def test_wrong_rule_file_format(test_app):
    result = decode_response(test_app.post('/rest/binary_search', json={'rule_file': 'not an actual rule file'}))
    assert 'Error in YARA rule file' in result['error_message']


def test_firmware_uid_not_found(test_app):
    data = {'rule_file': YARA_TEST_RULE, 'uid': 'not found'}
    result = decode_response(test_app.post('/rest/binary_search', json=data))
    assert 'not found in database' in result['error_message']


def test_start_binary_search(test_app):
    result = decode_response(test_app.post('/rest/binary_search', json={'rule_file': YARA_TEST_RULE}))
    assert 'Started binary search' in result['message']


def test_start_binary_search_with_uid(test_app):
    data = {'rule_file': YARA_TEST_RULE, 'uid': 'uid_in_db'}
    result = decode_response(test_app.post('/rest/binary_search', json=data))
    assert 'Started binary search' in result['message']


def test_get_result_without_search_id(test_app):
    result = decode_response(test_app.get('/rest/binary_search'))
    assert 'The method is not allowed for the requested URL' in result['message']


def test_get_result_non_existent_id(test_app):
    result = decode_response(test_app.get('/rest/binary_search/foobar'))
    assert 'result is not ready yet' in result['error_message']

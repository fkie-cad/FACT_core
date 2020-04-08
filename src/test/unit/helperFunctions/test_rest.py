import pytest

from helperFunctions.rest import (
    convert_rest_request, error_message, get_current_gmt, get_inverted_flag, get_paging, get_query, get_recursive_flag,
    get_summary_flag, get_tar_flag, get_update, success_message
)


def test_time_is_int():
    assert isinstance(get_current_gmt(), int)


def test_success_message_bad_type():
    with pytest.raises(TypeError):
        success_message(None, '/any/url')

    with pytest.raises(TypeError):
        success_message('Done some stuff. Didn\'t look for standards.', '/any/url')


def test_success_message_succeeds():
    message, code = success_message({'my': 'response'}, '/any/url')
    assert message['my'] == 'response'
    assert message['status'] == 0
    assert code == 200

    _, code = success_message({'my': 'response'}, '/any/url', return_code=202)
    assert code == 202


def test_error_message_bad_type():
    with pytest.raises(TypeError):
        error_message(None, '/any/url')

    with pytest.raises(TypeError):
        error_message({'Done some stuff': 'Didn\'t look for standards.'}, '/any/url')


def test_error_message_succeeds():
    message, code = error_message('my error response', '/any/url')
    assert message['error_message'] == 'my error response'
    assert message['status'] == 1
    assert code == 400

    _, code = error_message('my error response', '/any/url', return_code=304)
    assert code == 304


def test_messages_with_request_data():
    request_data = {'for_example': 'some uids'}
    message, _ = success_message({'my': 'data'}, '/any/url', request_data=request_data)
    assert message['request'] == request_data

    message, _ = error_message('my_error', '/any/url', request_data=request_data)
    assert message['request'] == request_data


@pytest.mark.parametrize('data', [None, dict(), b'', b'{"param": False}', b'{1, 2, 3}'])
def test_convert_rest_request_fails(data):
    with pytest.raises(TypeError):
        convert_rest_request(data)


@pytest.mark.parametrize('data', [b'{}', b'{"param": true}', b'{"a": 1, "b": {"c": 3}}'])
def test_convert_rest_request_succeeds(data):
    assert isinstance(convert_rest_request(data), dict)


def test_get_recursive():
    assert not get_recursive_flag(None)

    with pytest.raises(ValueError):
        get_recursive_flag(dict(recursive='bad_string'))

    with pytest.raises(ValueError):
        get_recursive_flag(dict(recursive='2'))

    no_flag = get_recursive_flag(dict())
    assert not no_flag

    false_result = get_recursive_flag(dict(recursive='false'))
    assert not false_result

    good_result = get_recursive_flag(dict(recursive='true'))
    assert good_result


@pytest.mark.parametrize('get_request_parameter_function, name', [
    (get_recursive_flag, 'recursive'),
    (get_inverted_flag, 'inverted'),
    (get_summary_flag, 'summary'),
    (get_tar_flag, 'tar'),
])
def test_get_boolean_from_request(get_request_parameter_function, name):
    assert not get_request_parameter_function(None)

    with pytest.raises(ValueError):
        get_request_parameter_function({name: 'bad_string'})

    no_flag = get_request_parameter_function(dict())
    assert not no_flag

    false_result = get_request_parameter_function({name: 'false'})
    assert not false_result

    good_result = get_request_parameter_function({name: 'true'})
    assert good_result


@pytest.mark.parametrize('arguments', [None, dict(), dict(update='bad_string'), dict(update='[]'), dict(update='{}')])
def test_get_update_bad(arguments):
    with pytest.raises(ValueError):
        get_update(arguments)


def test_get_update_success():
    assert get_update(dict(update='["any_plugin"]')) == ['any_plugin']


@pytest.mark.parametrize('arguments', [dict(query='bad_string'), dict(query='[]')])
def test_get_query_bad(arguments):
    with pytest.raises(ValueError):
        get_query(arguments)


def test_get_query():
    assert not get_query(None)

    assert get_query(dict(query='{"a": "b"}')) == {'a': 'b'}


@pytest.mark.parametrize('offset, limit', [(None, None), ('1', None), ('A', 'B')])
def test_get_paging_bad_arguments(offset, limit):
    with pytest.raises(ValueError):
        _ = get_paging(dict(offset=offset, limit=limit))


@pytest.mark.parametrize('request_args', [dict(offset=0, limit=1), dict(offset='0', limit='1')])
def test_get_paging_success(request_args):
    offset, limit = get_paging(request_args)
    assert (offset, limit) == (0, 1)

import pytest

from helperFunctions.rest import success_message, error_message, get_current_gmt, convert_rest_request, get_recursive, get_summary_flag, get_update, get_query, get_paging, get_tar_flag


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
    assert not get_recursive(None)

    with pytest.raises(ValueError):
        get_recursive(dict(recursive='bad_string'))

    with pytest.raises(ValueError):
        get_recursive(dict(recursive='2'))

    no_flag = get_recursive(dict())
    assert not no_flag

    false_result = get_recursive(dict(recursive='false'))
    assert not false_result

    good_result = get_recursive(dict(recursive='true'))
    assert good_result


def test_get_summary_flag():
    assert not get_summary_flag(None)

    with pytest.raises(ValueError):
        get_summary_flag(dict(summary='bad_string'))

    with pytest.raises(ValueError):
        get_summary_flag(dict(summary='2'))

    no_flag = get_summary_flag(dict())
    assert not no_flag

    false_result = get_summary_flag(dict(summary='false'))
    assert not false_result

    good_result = get_summary_flag(dict(summary='true'))
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


@pytest.mark.parametrize('arguments', [(None, None), ('1', None), ('A', 'B')])
def test_get_paging_bad_arguments(arguments):
    offset, limit = arguments
    paging, success = get_paging(dict(offset=offset, limit=limit))
    assert not success


def test_get_paging_success():
    paging, success = get_paging(dict(offset=0, limit=1))
    assert success and paging == (0, 1)

    paging, success = get_paging(dict(offset='0', limit='1'))
    assert success and paging == (0, 1)


def test_get_tar_flag_success():
    assert get_tar_flag(dict()) is False

    assert get_tar_flag(dict(tar='false')) is False
    assert get_tar_flag(dict(tar='true')) is True


@pytest.mark.parametrize('parameter', [None, '12', 'False'])
def test_get_tar_flag_raises(parameter):
    with pytest.raises(ValueError):
        get_tar_flag(dict(tar=parameter))

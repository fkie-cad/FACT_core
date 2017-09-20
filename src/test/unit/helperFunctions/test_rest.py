from helperFunctions.rest import success_message, error_message, get_current_gmt, convert_rest_request
import pytest


def test_time_is_int():
    assert isinstance(get_current_gmt(), int)


def test_success_message_bad_type():
    with pytest.raises(AssertionError):
        success_message(None, '/any/url')

    with pytest.raises(AssertionError):
        success_message('Done some stuff. Didn\'t look for standards.', '/any/url')


def test_success_message_succeeds():
    message, code = success_message({'my': 'response'}, '/any/url')
    assert message['my'] == 'response'
    assert message['status'] == 0
    assert code == 200

    _, code = success_message({'my': 'response'}, '/any/url', return_code=202)
    assert code == 202


def test_error_message_bad_type():
    with pytest.raises(AssertionError):
        error_message(None, '/any/url')

    with pytest.raises(AssertionError):
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

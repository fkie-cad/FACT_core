from base64 import standard_b64decode

from test.common_helper import TEST_FW

from .conftest import decode_response


def test_bad_requests(test_app):
    result = test_app.get('/rest/binary').data
    assert b'404 Not Found' in result

    result = test_app.get('/rest/binary/').data
    assert b'404 Not Found' in result


def test_non_existing_uid(test_app):
    result = decode_response(test_app.get('/rest/binary/some_uid'))
    assert 'No firmware with UID some_uid' in result['error_message']


def test_successful_download(test_app):
    result = decode_response(test_app.get('/rest/binary/{}'.format(TEST_FW.uid)))
    assert result['SHA256'] == TEST_FW.uid.split('_')[0]
    assert result['file_name'] == 'test.zip'
    assert isinstance(standard_b64decode(result['binary']), bytes)


def test_successful_tar_download(test_app):
    result = decode_response(test_app.get('/rest/binary/{}?tar=true'.format(TEST_FW.uid)))
    assert result['file_name'] == 'test.zip.tar.gz'
    assert isinstance(standard_b64decode(result['binary']), bytes)


def test_bad_tar_flag(test_app):
    result = decode_response(test_app.get('/rest/binary/{}?tar=True'.format(TEST_FW.uid)))
    assert result['status'] == 1
    assert 'tar must be true or false' in result['error_message']

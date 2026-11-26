from base64 import standard_b64decode
from http import HTTPStatus

import pytest

from test.common_helper import TEST_FW, TEST_TEXT_FILE, CommonDatabaseMock
from test.unit.conftest import CommonIntercomMock


def test_bad_requests(test_client):
    result = test_client.get('/rest/binary').data
    assert b'404 Not Found' in result


def test_non_existing_uid(test_client):
    result = test_client.get('/rest/binary/some_uid').json
    assert 'No firmware with UID some_uid' in result['error_message']


def test_successful_download(test_client):
    result = test_client.get(f'/rest/binary/{TEST_FW.uid}').json
    assert result['SHA256'] == TEST_FW.uid.split('_')[0]
    assert result['file_name'] == 'test.zip'
    assert isinstance(standard_b64decode(result['binary']), bytes)


def test_successful_tar_download(test_client):
    result = test_client.get(f'/rest/binary/{TEST_FW.uid}?tar=true').json
    assert result['file_name'] == 'test.zip.tar.gz'
    assert isinstance(standard_b64decode(result['binary']), bytes)


def test_bad_tar_flag(test_client):
    result = test_client.get(f'/rest/binary/{TEST_FW.uid}?tar=True').json
    assert result['status'] == 1
    assert 'tar must be true or false' in result['error_message']


class TarDbMock(CommonDatabaseMock):
    def is_firmware(self, uid):
        return uid == TEST_FW.uid


class TarIntercomMock(CommonIntercomMock):
    def get_repacked_file(self, uid):
        return b'tar of one layer'

    def get_recursively_repacked_file(self, uid):
        return b'tar of all layers'


with_tar_mocks = pytest.mark.WebInterfaceUnitTestConfig(
    database_mock_class=TarDbMock, intercom_mock_class=TarIntercomMock
)


@with_tar_mocks
def test_recursive_tar_download(test_client):
    result = test_client.get(f'/rest/binary/{TEST_FW.uid}?tar=true&recursive=true').json
    assert standard_b64decode(result['binary']) == b'tar of all layers'
    assert result['file_name'] == 'test.zip.tar.gz'
    assert result['request']['recursive'] is True


@with_tar_mocks
def test_tar_download_without_recursive_is_one_layer(test_client):
    result = test_client.get(f'/rest/binary/{TEST_FW.uid}?tar=true').json
    assert standard_b64decode(result['binary']) == b'tar of one layer'


@with_tar_mocks
def test_recursive_tar_download_only_for_firmware(test_client):
    response = test_client.get(f'/rest/binary/{TEST_TEXT_FILE.uid}?tar=true&recursive=true')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert 'recursive tar archive is only available for firmware' in response.json['error_message']


@with_tar_mocks
def test_recursive_needs_tar(test_client):
    response = test_client.get(f'/rest/binary/{TEST_FW.uid}?recursive=true')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert 'recursive=true requires tar=true' in response.json['error_message']


@with_tar_mocks
def test_bad_recursive_flag(test_client):
    response = test_client.get(f'/rest/binary/{TEST_FW.uid}?tar=true&recursive=yes')
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert 'recursive must be true or false' in response.json['error_message']

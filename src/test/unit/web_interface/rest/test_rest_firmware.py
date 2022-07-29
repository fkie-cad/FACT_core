# pylint: disable=no-self-use
import json
from base64 import standard_b64encode
from copy import deepcopy
from urllib.parse import quote

import pytest

from test.common_helper import TEST_FW, CommonDatabaseMock

TEST_FW_PAYLOAD = {
    'binary': standard_b64encode(b'\x01\x23\x45\x67\x89').decode(),
    'file_name': 'no_real_file',
    'device_part': 'kernel',
    'device_name': 'no real device',
    'device_class': 'no real class',
    'version': 'no.real.version',
    'release_date': '1970-01-01',
    'vendor': 'no real vendor',
    'tags': 'tag1,tag2',
    'requested_analysis_systems': ['file_type']
}


class DbMock(CommonDatabaseMock):
    @staticmethod
    def rest_get_firmware_uids(limit: int = 10, offset: int = 0, query=None, recursive=False, inverted=False):  # pylint: disable=unused-argument
        return [f'uid{i}' for i in range(offset, limit or 10)]

    @staticmethod
    def get_complete_object_including_all_summaries(uid):
        fw = deepcopy(TEST_FW)
        fw.processed_analysis['dummy']['summary'] = {'included_files': 'summary'}
        return fw if uid == fw.uid else None


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_successful_request(test_client):
    response = test_client.get('/rest/firmware').json
    assert 'error_message' not in response
    assert 'uids' in response
    assert len(response['uids']) == 10


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_request_with_query(test_client):
    query = {'vendor': 'no real vendor'}
    quoted_query = quote(json.dumps(query))
    response = test_client.get(f'/rest/firmware?query={quoted_query}').json
    assert 'query' in response['request'].keys()
    assert response['request']['query'] == query


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_bad_query(test_client):
    search_query = quote('{\'vendor\': \'no real vendor\'}')
    result = test_client.get(f'/rest/firmware?query={search_query}').json
    assert 'Query must be a json' in result['error_message']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_empty_response(test_client):
    response = test_client.get('/rest/firmware?limit=1').json
    assert 'error_message' not in response
    assert len(response['uids']) == 1

    response = test_client.get('/rest/firmware?offset=10').json
    assert 'error_message' not in response
    assert len(response['uids']) == 0


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_bad_paging(test_client):
    response = test_client.get('/rest/firmware?offset=X&limit=V').json
    assert 'error_message' in response
    assert 'Malformed' in response['error_message']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_non_existing_uid(test_client):
    result = test_client.get('/rest/firmware/some_uid').json
    assert 'No firmware with UID some_uid' in result['error_message']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_successful_uid_request(test_client):
    result = test_client.get(f'/rest/firmware/{TEST_FW.uid}').json
    assert 'firmware' in result
    assert all(section in result['firmware'] for section in ['meta_data', 'analysis'])


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_bad_put_request(test_client):
    result = test_client.put('/rest/firmware').json
    assert 'Input payload validation failed' in result['message']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_submit_empty_data(test_client):
    result = test_client.put('/rest/firmware', data=json.dumps({})).json
    assert 'Input payload validation failed' in result['message']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_submit_missing_item(test_client):
    request_data = {**TEST_FW_PAYLOAD}
    request_data.pop('vendor')
    result = test_client.put('/rest/firmware', json=request_data).json
    assert 'Input payload validation failed' in result['message']
    assert 'vendor' in result['errors']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_submit_invalid_binary(test_client):
    request_data = {**TEST_FW_PAYLOAD, 'binary': 'invalid_base64'}
    result = test_client.put('/rest/firmware', json=request_data).json
    assert 'Could not parse binary (must be valid base64!)' in result['error_message']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_submit_success(test_client):
    result = test_client.put('/rest/firmware', json=TEST_FW_PAYLOAD).json
    assert result['status'] == 0


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_request_update(test_client):
    requested_analysis = json.dumps(['optional_plugin'])
    result = test_client.put(f'/rest/firmware/{TEST_FW.uid}?update={quote(requested_analysis)}').json
    assert result['status'] == 0


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_submit_no_tags(test_client):
    request_data = {**TEST_FW_PAYLOAD}
    request_data.pop('tags')
    result = test_client.put('/rest/firmware', json=request_data).json
    assert result['status'] == 0


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_submit_no_release_date(test_client):
    request_data = {**TEST_FW_PAYLOAD}
    request_data.pop('release_date')
    result = test_client.put('/rest/firmware', json=request_data).json
    assert result['status'] == 0
    assert isinstance(result['request']['release_date'], str)
    assert result['request']['release_date'] == '1970-01-01'


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_submit_invalid_release_date(test_client):
    request_data = {**TEST_FW_PAYLOAD, 'release_date': 'invalid date'}
    result = test_client.put('/rest/firmware', json=request_data).json
    assert result['status'] == 1
    assert 'Invalid date literal' in result['error_message']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_request_update_bad_parameter(test_client):
    result = test_client.put(f'/rest/firmware/{TEST_FW.uid}?update=no_list').json
    assert result['status'] == 1
    assert 'has to be a list' in result['error_message']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_request_update_missing_parameter(test_client):  # pylint: disable=invalid-name
    result = test_client.put(f'/rest/firmware/{TEST_FW.uid}').json
    assert result['status'] == 1
    assert 'missing parameter: update' in result['error_message']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_request_with_unpacking(test_client):
    scheduled_analysis = ['unpacker', 'optional_plugin']
    requested_analysis = json.dumps(scheduled_analysis)
    result = test_client.put(f'/rest/firmware/{TEST_FW.uid}?update={quote(requested_analysis)}').json
    assert result['status'] == 0
    assert sorted(result['request']['update']) == sorted(scheduled_analysis)
    assert 'unpacker' in result['request']['update']


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_request_with_bad_recursive_flag(test_client):  # pylint: disable=invalid-name
    result = test_client.get('/rest/firmware?recursive=true').json
    assert result['status'] == 1
    assert 'only permissible with non-empty query' in result['error_message']

    query = json.dumps({'processed_analysis.file_type.full': {'$regex': 'arm', '$options': 'si'}})
    result = test_client.get(f'/rest/firmware?recursive=true&query={quote(query)}').json
    assert result['status'] == 0


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_request_with_inverted_flag(test_client):
    result = test_client.get('/rest/firmware?inverted=true&query={"foo": "bar"}').json
    assert result['status'] == 1
    assert 'Inverted flag can only be used with recursive' in result['error_message']

    result = test_client.get('/rest/firmware?inverted=true&recursive=true&query={"foo": "bar"}').json
    assert result['status'] == 0


@pytest.mark.DatabaseMockClass(lambda: DbMock)
def test_request_with_summary(test_client):
    result = test_client.get(f'/rest/firmware/{TEST_FW.uid}?summary=true').json
    assert 'firmware' in result
    assert 'summary' in result['firmware']['analysis']['dummy'], 'included file summaries should be included'

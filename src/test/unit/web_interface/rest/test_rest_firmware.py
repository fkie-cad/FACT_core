import json
from base64 import standard_b64encode
from copy import deepcopy
from http import HTTPStatus
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
    'requested_analysis_systems': ['file_type'],
}


class DbMock(CommonDatabaseMock):
    @staticmethod
    def rest_get_firmware_uids(
        limit: int = 10,
        offset: int = 0,
        query=None,  # noqa: ARG004
        recursive=False,  # noqa: ARG004
        inverted=False,  # noqa: ARG004
    ):
        return [f'uid{i}' for i in range(offset, limit or 10)]

    @staticmethod
    def get_complete_object_including_all_summaries(uid):
        fw = deepcopy(TEST_FW)
        fw.processed_analysis['dummy']['summary'] = {'included_files': 'summary'}
        return fw if uid == fw.uid else None


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
class TestRestFirmware:
    def test_successful_request(self, test_client):
        response = test_client.get('/rest/firmware').json
        assert 'error_message' not in response
        assert 'uids' in response
        assert len(response['uids']) == 10

    def test_request_with_query(self, test_client):
        query = {'vendor': 'no real vendor'}
        quoted_query = quote(json.dumps(query))
        response = test_client.get(f'/rest/firmware?query={quoted_query}').json
        assert 'query' in response['request']
        assert response['request']['query'] == query

    def test_bad_query(self, test_client):
        search_query = quote("{'vendor': 'no real vendor'}")
        result = test_client.get(f'/rest/firmware?query={search_query}').json
        assert 'Query must be a json' in result['error_message']

    def test_empty_response(self, test_client):
        response = test_client.get('/rest/firmware?limit=1').json
        assert 'error_message' not in response
        assert len(response['uids']) == 1

        response = test_client.get('/rest/firmware?offset=10').json
        assert 'error_message' not in response
        assert len(response['uids']) == 0

    def test_bad_paging(self, test_client):
        response = test_client.get('/rest/firmware?offset=X&limit=V').json
        assert 'error_message' in response
        assert 'Malformed' in response['error_message']

    def test_non_existing_uid(self, test_client):
        result = test_client.get('/rest/firmware/some_uid').json
        assert 'No firmware with UID some_uid' in result['error_message']

    def test_successful_uid_request(self, test_client):
        result = test_client.get(f'/rest/firmware/{TEST_FW.uid}').json
        assert 'firmware' in result
        assert all(section in result['firmware'] for section in ['meta_data', 'analysis'])

    def test_bad_put_request(self, test_client):
        response = test_client.put('/rest/firmware')
        assert response.status_code == HTTPStatus.UNSUPPORTED_MEDIA_TYPE

    def test_submit_empty_data(self, test_client):
        response = test_client.put('/rest/firmware', json={}).json
        assert 'Input payload validation failed' in response['message']

    def test_submit_missing_item(self, test_client):
        request_data = {**TEST_FW_PAYLOAD}
        request_data.pop('vendor')
        result = test_client.put('/rest/firmware', json=request_data).json
        assert 'Input payload validation failed' in result['message']
        assert 'vendor' in result['errors']

    def test_submit_invalid_binary(self, test_client):
        request_data = {**TEST_FW_PAYLOAD, 'binary': 'invalid_base64'}
        result = test_client.put('/rest/firmware', json=request_data).json
        assert 'Could not parse binary (must be valid base64!)' in result['error_message']

    def test_submit_success(self, test_client):
        result = test_client.put('/rest/firmware', json=TEST_FW_PAYLOAD).json
        assert result['status'] == 0

    def test_request_update(self, test_client):
        requested_analysis = json.dumps(['optional_plugin'])
        result = test_client.put(f'/rest/firmware/{TEST_FW.uid}?update={quote(requested_analysis)}').json
        assert result['status'] == 0

    def test_submit_no_tags(self, test_client):
        request_data = {**TEST_FW_PAYLOAD}
        request_data.pop('tags')
        result = test_client.put('/rest/firmware', json=request_data).json
        assert result['status'] == 0

    def test_submit_no_release_date(self, test_client):
        request_data = {**TEST_FW_PAYLOAD}
        request_data.pop('release_date')
        result = test_client.put('/rest/firmware', json=request_data).json
        assert result['status'] == 0
        assert isinstance(result['request']['release_date'], str)
        assert result['request']['release_date'] == '1970-01-01'

    def test_submit_invalid_release_date(self, test_client):
        request_data = {**TEST_FW_PAYLOAD, 'release_date': 'invalid date'}
        result = test_client.put('/rest/firmware', json=request_data).json
        assert result['status'] == 1
        assert 'Invalid date literal' in result['error_message']

    def test_request_update_bad_parameter(self, test_client):
        result = test_client.put(f'/rest/firmware/{TEST_FW.uid}?update=no_list').json
        assert result['status'] == 1
        assert 'has to be a list' in result['error_message']

    def test_request_update_missing_parameter(self, test_client):
        result = test_client.put(f'/rest/firmware/{TEST_FW.uid}').json
        assert result['status'] == 1
        assert 'missing parameter: update' in result['error_message']

    def test_request_with_unpacking(self, test_client):
        scheduled_analysis = ['unpacker', 'optional_plugin']
        requested_analysis = json.dumps(scheduled_analysis)
        result = test_client.put(f'/rest/firmware/{TEST_FW.uid}?update={quote(requested_analysis)}').json
        assert result['status'] == 0
        assert sorted(result['request']['update']) == sorted(scheduled_analysis)
        assert 'unpacker' in result['request']['update']

    def test_request_with_bad_recursive_flag(self, test_client):
        result = test_client.get('/rest/firmware?recursive=true').json
        assert result['status'] == 1
        assert 'only permissible with non-empty query' in result['error_message']

        query = json.dumps({'processed_analysis.file_type.full': {'$regex': 'arm', '$options': 'si'}})
        result = test_client.get(f'/rest/firmware?recursive=true&query={quote(query)}').json
        assert result['status'] == 0

    def test_request_with_inverted_flag(self, test_client):
        result = test_client.get('/rest/firmware?inverted=true&query={"foo": "bar"}').json
        assert result['status'] == 1
        assert 'Inverted flag can only be used with recursive' in result['error_message']

        result = test_client.get('/rest/firmware?inverted=true&recursive=true&query={"foo": "bar"}').json
        assert result['status'] == 0

    def test_request_with_summary(self, test_client):
        result = test_client.get(f'/rest/firmware/{TEST_FW.uid}?summary=true').json
        assert 'firmware' in result
        assert 'summary' in result['firmware']['analysis']['dummy'], 'included file summaries should be included'

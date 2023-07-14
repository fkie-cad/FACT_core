import json
import urllib.parse

import pytest

from test.common_helper import get_firmware_for_rest_upload_test

test_container_uid = '418a54d78550e8584291c96e5d6168133621f352bfc1d43cf84e81187fef4962_787'


class TestRestFirmware:
    def _rest_upload_firmware(self, test_client):
        data = get_firmware_for_rest_upload_test()
        rv = test_client.put('/rest/firmware', json=data, follow_redirects=True)
        assert b'"status": 0' in rv.data, 'rest upload not successful'
        assert test_container_uid.encode() in rv.data, 'uid not found in rest upload reply'

    def _rest_get_analysis_result(self, test_client):
        rv = test_client.get(f'/rest/firmware/{test_container_uid}', follow_redirects=True)
        assert b'analysis_date' in rv.data, 'rest analysis download not successful'
        assert b'software_components' in rv.data, 'rest analysis not successful'
        assert b'"device_part": "test_part' in rv.data, 'device part not present'

    def _rest_search(self, test_client):
        query = urllib.parse.quote('{"device_class": "test_class"}')
        rv = test_client.get(f'/rest/firmware?query={query}', follow_redirects=True)
        assert test_container_uid.encode() in rv.data, 'test firmware not found in rest search'

    def _rest_search_fw_only(self, test_client):
        query = json.dumps({'sha256': test_container_uid.split('_')[0]})
        rv = test_client.get(f'/rest/firmware?query={urllib.parse.quote(query)}', follow_redirects=True)
        assert test_container_uid.encode() in rv.data, 'test firmware not found in rest search'

    def _rest_update_analysis_bad_analysis(self, test_client):
        query = urllib.parse.quote('["unknown_system"]')
        rv = test_client.put(f'/rest/firmware/{test_container_uid}?update={query}', follow_redirects=True)
        assert (
            b'Unknown analysis system' in rv.data
        ), 'rest analysis update should break on request of non existing system'

    def _rest_update_analysis_success(self, test_client):
        update = urllib.parse.quote(json.dumps(['crypto_material']))
        rv = test_client.put(f'/rest/firmware/{test_container_uid}?update={update}', follow_redirects=True)
        assert b'error_message' not in rv.data, 'Error on update request'

    def _rest_check_new_analysis_exists(self, test_client):
        rv = test_client.get(f'/rest/firmware/{test_container_uid}', follow_redirects=True)
        response_data = json.loads(rv.data.decode())
        assert response_data['firmware']['analysis']['crypto_material']
        assert (
            response_data['firmware']['analysis']['crypto_material']['analysis_date']
            > response_data['firmware']['analysis']['software_components']['analysis_date']
        )

    @pytest.mark.usefixtures('intercom_backend_binding')
    # container including 3 files times 3 plugins
    @pytest.mark.SchedulerTestConfig(items_to_analyze=4 * 3)
    def test_run_from_upload_to_show_analysis_and_search(
        self, test_client, analysis_finished_event, analysis_finished_counter
    ):
        self._rest_upload_firmware(test_client)
        assert analysis_finished_event.wait(timeout=15)
        analysis_finished_counter.value -= 4  # only one plugin to update
        analysis_finished_event.clear()
        self._rest_get_analysis_result(test_client)
        self._rest_search(test_client)
        self._rest_search_fw_only(test_client)
        self._rest_update_analysis_bad_analysis(test_client)
        self._rest_update_analysis_success(test_client)

        assert analysis_finished_event.wait(timeout=10)

        self._rest_check_new_analysis_exists(test_client)

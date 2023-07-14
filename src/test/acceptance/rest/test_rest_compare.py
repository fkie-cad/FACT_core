import urllib.parse
from base64 import standard_b64encode
from pathlib import Path

import pytest

from test.acceptance.conftest import test_fw_a, test_fw_c
from test.common_helper import get_test_data_dir


class TestRestCompareFirmware:
    def _rest_upload_firmware(self, test_client, fw):
        testfile_path = Path(get_test_data_dir()) / fw.path
        file_content = testfile_path.read_bytes()
        data = {
            'binary': standard_b64encode(file_content).decode(),
            'file_name': 'test.zip',
            'device_name': 'test_device',
            'device_part': 'full',
            'device_class': 'test_class',
            'version': '1.0',
            'vendor': 'test_vendor',
            'release_date': '1970-01-01',
            'tags': '',
            'requested_analysis_systems': ['software_components'],
        }
        rv = test_client.put('/rest/firmware', json=data, follow_redirects=True)
        assert b'"status": 0' in rv.data, 'rest upload not successful'
        assert fw.uid.encode() in rv.data, 'uid not found in REST upload reply'

    def _rest_search(self, test_client, fw):
        query = urllib.parse.quote('{"device_class": "test_class"}')
        rv = test_client.get(f'/rest/firmware?query={query}', follow_redirects=True)
        assert fw.uid.encode() in rv.data, 'test firmware not found in REST search'

    def _rest_start_compare(self, test_client):
        data = {'uid_list': [test_fw_a.uid, test_fw_c.uid]}
        rv = test_client.put('/rest/compare', json=data, follow_redirects=True)
        assert b'Compare started' in rv.data, 'could not start REST compare'

    def _rest_get_compare(self, test_client):
        rv = test_client.get(f'/rest/compare/{test_fw_a.uid};{test_fw_c.uid}', follow_redirects=True)
        assert b'Compare not found in database.' not in rv.data, 'compare not found in database'
        assert b'"files_in_common": {"' in rv.data, 'REST compare not successful'

    # two firmware container with 3 included files each times three plugins
    @pytest.mark.SchedulerTestConfig(items_to_analyze=4 * 2 * 3)
    @pytest.mark.usefixtures('intercom_backend_binding')
    def test_run_from_upload_to_show_analysis(self, test_client, analysis_finished_event, comparison_finished_event):
        self._rest_upload_firmware(test_client, test_fw_a)
        self._rest_upload_firmware(test_client, test_fw_c)
        assert analysis_finished_event.wait(timeout=20)
        self._rest_search(test_client, test_fw_a)
        self._rest_search(test_client, test_fw_c)
        self._rest_start_compare(test_client)
        assert comparison_finished_event.wait(timeout=20)
        self._rest_get_compare(test_client)

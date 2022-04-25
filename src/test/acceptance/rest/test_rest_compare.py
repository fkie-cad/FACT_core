# pylint: disable=no-self-use
import urllib.parse
from base64 import standard_b64encode
from pathlib import Path

from test.common_helper import get_test_data_dir


class TestRestCompareFirmware:
    def _rest_upload_firmware(self, fw, test_client):
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
            'requested_analysis_systems': ['software_components']
        }
        rv = test_client.put('/rest/firmware', json=data, follow_redirects=True)
        assert b'"status": 0' in rv.data, 'rest upload not successful'
        assert fw.uid.encode() in rv.data, 'uid not found in REST upload reply'

    def _rest_search(self, fw, test_client):
        query = urllib.parse.quote('{"device_class": "test_class"}')
        rv = test_client.get(f'/rest/firmware?query={query}', follow_redirects=True)
        assert fw.uid.encode() in rv.data, 'test firmware not found in REST search'

    def _rest_start_compare(self, test_client, test_fw_a, test_fw_c):
        data = {'uid_list': [test_fw_a.uid, test_fw_c.uid]}
        rv = test_client.put('/rest/compare', json=data, follow_redirects=True)
        assert b'Compare started' in rv.data, 'could not start REST compare'

    def _rest_get_compare(self, test_client, test_fw_a, test_fw_c):
        rv = test_client.get(f'/rest/compare/{test_fw_a.uid};{test_fw_c.uid}', follow_redirects=True)
        assert b'Compare not found in database.' not in rv.data, 'compare not found in database'
        assert b'"files_in_common": {"' in rv.data, 'REST compare not successful'

    def test_run_from_upload_to_show_analysis(
        self,
        backend_services,
        test_client,
        test_fw_a,
        test_fw_c,
        analysis_finished_event,
        compare_finished_event,
    ):
        self._rest_upload_firmware(test_fw_a, test_client)
        self._rest_upload_firmware(test_fw_c, test_client)
        analysis_finished_event.wait(timeout=20)
        self._rest_search(test_fw_a, test_client)
        self._rest_search(test_fw_c, test_client)
        self._rest_start_compare(test_client, test_fw_a, test_fw_c)
        compare_finished_event.wait(timeout=20)
        self._rest_get_compare(test_client, test_fw_a, test_fw_c)

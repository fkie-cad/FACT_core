# pylint: disable=wrong-import-order
import json
from pathlib import Path
from time import sleep, time

from storage.fsorganizer import FSOrganizer
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import get_firmware_for_rest_upload_test

# the file inside the uploaded test file, that is matched by the binary search
MATCH_FILE_UID = 'd558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62'


class TestRestBinarySearch(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.fs_organizer = FSOrganizer()

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    def test_binary_search(self):
        self._upload_firmware()
        self._wait_for_binary(Path(self.fs_organizer.generate_path_from_uid(MATCH_FILE_UID)))
        search_id = self._post_binary_search()
        self._get_binary_search_result(search_id)

    def _upload_firmware(self):
        data = get_firmware_for_rest_upload_test()
        rv = self.test_client.put('/rest/firmware', json=data, follow_redirects=True)
        assert 'uid' in rv.json, 'rest upload not successful'

    def _post_binary_search(self):
        data = {'rule_file': 'rule rulename {strings: $a = "MyTestRule" condition: $a }'}
        rv = self.test_client.post('/rest/binary_search', json=data, follow_redirects=True)
        result = json.loads(rv.data.decode())
        assert 'message' in result
        assert 'Started binary search' in result['message']
        assert 'request' in result and 'search_id' in result['request']
        return result['request']['search_id']

    def _get_binary_search_result(self, search_id):
        rv = self.test_client.get(f'/rest/binary_search/{search_id}', follow_redirects=True)
        results = json.loads(rv.data.decode())
        assert 'binary_search_results' in results
        assert 'rulename' in results['binary_search_results']

    @staticmethod
    def _wait_for_binary(path: Path):
        timeout = time() + 5
        while time() < timeout:
            if path.is_file():
                return
            sleep(0.5)
        raise TimeoutError('Binary not found after upload')

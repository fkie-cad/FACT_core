import json

from time import sleep

from test.acceptance.base import TestAcceptanceBase
from test.common_helper import get_firmware_for_rest_upload_test


class TestRestBinarySearch(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        sleep(1)  # wait for systems to start

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    def test_binary_search(self):
        self._upload_firmware()
        sleep(2)  # wait for binary to be saved
        search_id = self._post_binary_search()
        self._get_binary_search_result(search_id)

    def _upload_firmware(self):
        data = get_firmware_for_rest_upload_test()
        rv = self.test_client.put('/rest/firmware', data=json.dumps(data), follow_redirects=True)
        self.assertIn(b'"status": 0', rv.data, 'rest upload not successful')

    def _post_binary_search(self):
        data = {'rule_file': 'rule rulename {strings: $a = "MyTestRule" condition: $a }'}
        rv = self.test_client.post('/rest/binary_search', data=json.dumps(data), follow_redirects=True)
        result = json.loads(rv.data.decode())
        assert 'message' in result
        assert 'Started binary search' in result['message']
        assert 'request' in result and 'search_id' in result['request']
        return result['request']['search_id']

    def _get_binary_search_result(self, search_id):
        rv = self.test_client.get('/rest/binary_search/{}'.format(search_id), follow_redirects=True)
        results = json.loads(rv.data.decode())
        assert 'binary_search_results' in results
        assert 'rulename' in results['binary_search_results']

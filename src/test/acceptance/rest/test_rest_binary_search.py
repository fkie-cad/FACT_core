import json
import time

from storage.db_interface_backend import BackEndDbInterface
from test.acceptance.base import TestAcceptanceBase
from test.common_helper import get_firmware_for_rest_upload_test


class TestRestBinarySearch(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend = BackEndDbInterface(config=self.config)
        time.sleep(1)  # wait for systems to start

    def tearDown(self):
        self.db_backend.shutdown()
        self._stop_backend()
        super().tearDown()

    def test_binary_search(self):
        self._upload_firmware()
        time.sleep(2)  # wait for binary to be saved

        data = {'rule_file': 'rule rulename {strings: $a = "MyTestRule" condition: $a }'}
        rv = self.test_client.post('/rest/binary_search', data=json.dumps(data), follow_redirects=True)
        result = json.loads(rv.data)
        assert 'message' in result
        assert 'Started binary search' in result['message']
        assert 'request' in result and 'search_id' in result['request']

        rv = self.test_client.get('/rest/binary_search/{}'.format(result['request']['search_id']), follow_redirects=True)
        result = json.loads(rv.data)
        assert 'binary_search_results' in result
        assert 'rulename' in result['binary_search_results']

    def _upload_firmware(self):
        data = get_firmware_for_rest_upload_test()
        rv = self.test_client.put('/rest/firmware', data=json.dumps(data), follow_redirects=True)
        self.assertIn(b'"status": 0', rv.data, 'rest upload not successful')

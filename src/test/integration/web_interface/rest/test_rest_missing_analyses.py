import json

from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_file_object, create_test_firmware
from test.integration.web_interface.rest.base import RestTestBase


class TestRestMissingAnalyses(RestTestBase):

    def setUp(self):
        super().setUp()
        self.db_backend = BackEndDbInterface(config=self.config)

    def tearDown(self):
        self.db_backend.shutdown()
        super().tearDown()

    def test_rest_get_missing_files(self):
        test_fw = create_test_firmware()
        missing_uid = 'uid1234'
        test_fw.files_included.add(missing_uid)
        self.db_backend.add_firmware(test_fw)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'missing_files' in response
        assert test_fw.uid in response['missing_files']
        assert missing_uid in response['missing_files'][test_fw.uid]
        assert response['missing_analyses'] == {}

    def test_rest_get_missing_analyses(self):
        test_fw = create_test_firmware()
        test_fo = create_test_file_object()
        test_fw.files_included.add(test_fo.uid)
        test_fo.virtual_file_path = {test_fw.uid: ['|foo|bar|']}
        test_fw.processed_analysis['foobar'] = {'foo': 'bar'}
        # test_fo is missing this analysis but is in files_included -> should count as missing analysis
        self.db_backend.add_firmware(test_fw)
        self.db_backend.add_file_object(test_fo)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'missing_analyses' in response
        assert test_fw.uid in response['missing_analyses']
        assert test_fo.uid in response['missing_analyses'][test_fw.uid]
        assert response['missing_files'] == {}

import json

from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_file_object, create_test_firmware
from test.integration.web_interface.rest.base import RestTestBase


class TestRestMissingAnalyses(RestTestBase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.db_backend = BackEndDbInterface(config=cls.config)

    @classmethod
    def tearDownClass(cls):
        cls.db_backend.shutdown()
        super().tearDownClass()

    def test_rest_get_missing_files(self):
        test_fw_1 = create_test_firmware()
        missing_uid = 'uid1234'
        test_fw_1.files_included.add(missing_uid)
        self.db_backend.add_firmware(test_fw_1)

        response = json.loads(self.test_client.get('/rest/missing_analyses', follow_redirects=True).data.decode())
        assert 'missing_files' in response
        assert test_fw_1.uid in response['missing_files']
        assert missing_uid in response['missing_files'][test_fw_1.uid]
        assert response.get('missing_analyses') == {}

    def test_rest_get_missing_analyses(self):
        test_fw_1 = create_test_firmware()
        test_fo = create_test_file_object()
        test_fw_1.files_included.add(test_fo.uid)
        test_fo.virtual_file_path = {test_fw_1.uid: ['|foo|bar|']}
        test_fw_1.processed_analysis['foobar'] = {'foo': 'bar'}
        self.db_backend.add_firmware(test_fw_1)
        self.db_backend.add_file_object(test_fo)

        response = json.loads(self.test_client.get('/rest/missing_analyses', follow_redirects=True).data.decode())
        assert 'missing_analyses' in response
        assert test_fw_1.uid in response['missing_analyses']
        assert test_fo.uid in response['missing_analyses'][test_fw_1.uid]
        assert response.get('missing_files') == {}

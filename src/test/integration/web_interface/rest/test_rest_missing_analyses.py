# pylint: disable=attribute-defined-outside-init

import json

from storage.db_interface_backend import BackEndDbInterface
from test.common_helper import create_test_file_object, create_test_firmware
from test.integration.web_interface.rest.base import RestTestBase


class TestRestMissingAnalyses(RestTestBase):

    def setup(self):
        super().setup()
        self.db_backend = BackEndDbInterface(config=self.config)

    def teardown(self):
        self.db_backend.shutdown()
        super().teardown()

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

    def test_rest_get_failed_analyses(self):
        test_fo = create_test_file_object()
        test_fo.processed_analysis['some_analysis'] = {'failed': 'oops'}
        self.db_backend.add_file_object(test_fo)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'failed_analyses' in response
        assert 'some_analysis' in response['failed_analyses']
        assert test_fo.uid in response['failed_analyses']['some_analysis']

    def test_rest_get_orphaned_objects(self):
        test_fo = create_test_file_object()
        test_fo.parent_firmware_uids = ['missing_uid']
        self.db_backend.add_file_object(test_fo)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'orphaned_objects' in response
        assert response['orphaned_objects'] == {
            'missing_uid': ['d558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62']
        }

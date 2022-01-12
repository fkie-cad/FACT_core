# pylint: disable=attribute-defined-outside-init,wrong-import-order

import json

import pytest

from test.common_helper import create_test_file_object, create_test_firmware
from test.integration.storage_postgresql.helper import generate_analysis_entry
from test.integration.web_interface.rest.base import RestTestBase


class TestRestMissingAnalyses(RestTestBase):

    @pytest.mark.skip('does not make sense with new DB')
    def test_rest_get_missing_files(self, db):
        test_fw = create_test_firmware()
        missing_uid = 'uid1234'
        test_fw.files_included.add(missing_uid)
        db.backend.add_object(test_fw)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'missing_files' in response
        assert test_fw.uid in response['missing_files']
        assert missing_uid in response['missing_files'][test_fw.uid]
        assert response['missing_analyses'] == {}

    def test_rest_get_missing_analyses(self, db):
        test_fw = create_test_firmware()
        test_fo = create_test_file_object()
        test_fw.files_included.add(test_fo.uid)
        test_fo.virtual_file_path = {test_fw.uid: ['|foo|bar|']}
        test_fo.parent_firmware_uids = [test_fw.uid]
        test_fw.processed_analysis['foobar'] = generate_analysis_entry(analysis_result={'foo': 'bar'})
        # test_fo is missing this analysis but is in files_included -> should count as missing analysis
        db.backend.add_object(test_fw)
        db.backend.add_object(test_fo)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'missing_analyses' in response
        assert test_fw.uid in response['missing_analyses']
        assert test_fo.uid in response['missing_analyses'][test_fw.uid]
        assert response['missing_files'] == {}

    def test_rest_get_failed_analyses(self, db):
        test_fo = create_test_file_object()
        test_fo.processed_analysis['some_analysis'] = generate_analysis_entry(analysis_result={'failed': 'oops'})
        db.backend.add_object(test_fo)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'failed_analyses' in response
        assert 'some_analysis' in response['failed_analyses']
        assert test_fo.uid in response['failed_analyses']['some_analysis']

    @pytest.mark.skip('does not make sense with new DB')
    def test_rest_get_orphaned_objects(self, db):
        test_fo = create_test_file_object()
        test_fo.parent_firmware_uids = ['missing_uid']
        db.backend.add_object(test_fo)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'orphaned_objects' in response
        assert response['orphaned_objects'] == {
            'missing_uid': ['d558c9339cb967341d701e3184f863d3928973fccdc1d96042583730b5c7b76a_62']
        }

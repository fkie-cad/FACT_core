import json

from fact.test.common_helper import create_test_file_object, create_test_firmware, generate_analysis_entry
from fact.test.integration.web_interface.rest.base import RestTestBase


class TestRestMissingAnalyses(RestTestBase):
    def test_rest_get_missing_analyses(self, backend_db):
        test_fw = create_test_firmware()
        test_fo = create_test_file_object()
        test_fw.files_included.add(test_fo.uid)
        test_fo.virtual_file_path = {test_fw.uid: ['|foo|bar|']}
        test_fo.parent_firmware_uids = [test_fw.uid]
        test_fw.processed_analysis['foobar'] = generate_analysis_entry(analysis_result={'foo': 'bar'})
        # test_fo is missing this analysis but is in files_included -> should count as missing analysis
        backend_db.add_object(test_fw)
        backend_db.add_object(test_fo)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'missing_analyses' in response
        assert test_fw.uid in response['missing_analyses']
        assert test_fo.uid in response['missing_analyses'][test_fw.uid]

    def test_rest_get_failed_analyses(self, backend_db):
        test_fo = create_test_file_object()
        test_fo.processed_analysis['some_analysis'] = generate_analysis_entry(analysis_result={'failed': 'oops'})
        backend_db.add_object(test_fo)

        response = json.loads(self.test_client.get('/rest/missing', follow_redirects=True).data.decode())
        assert 'failed_analyses' in response
        assert 'some_analysis' in response['failed_analyses']
        assert test_fo.uid in response['failed_analyses']['some_analysis']

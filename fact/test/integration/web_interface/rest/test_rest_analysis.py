from http import HTTPStatus

import pytest

from test.common_helper import generate_analysis_entry
from test.integration.storage.helper import insert_test_fo
from test.integration.web_interface.rest.base import RestTestBase

TYPE_RESULT = {'mime': 'mime_type', 'full': 'full type description'}


@pytest.mark.usefixtures('database_interfaces')
class TestRestAnalysis(RestTestBase):
    def test_rest_get_analysis(self, backend_db):
        insert_test_fo(
            backend_db,
            'uid',
            analysis={'file_type': generate_analysis_entry(analysis_result=TYPE_RESULT)},
        )

        response = self.test_client.get('/rest/analysis/uid/file_type')
        assert response.status_code == HTTPStatus.OK
        assert 'analysis' in response.json
        assert response.json['analysis']['result'] == TYPE_RESULT

    def test_rest_get_analysis_no_file(self):
        response = self.test_client.get('/rest/analysis/unknown_uid/file_type')
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert 'analysis' not in response.json
        assert 'error_message' in response.json
        assert 'No file object with UID' in response.json['error_message']

    def test_rest_get_analysis_missing(self, backend_db):
        insert_test_fo(backend_db, 'uid')

        response = self.test_client.get('/rest/analysis/uid/unknown_plugin')
        assert response.status_code == HTTPStatus.PRECONDITION_FAILED
        assert 'analysis' not in response.json
        assert 'error_message' in response.json
        assert 'not found' in response.json['error_message']

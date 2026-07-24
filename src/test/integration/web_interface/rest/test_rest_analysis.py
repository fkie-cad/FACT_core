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

    def test_rest_get_analysis_summary_flag(self, backend_db):
        insert_test_fo(
            backend_db,
            'uid',
            analysis={'file_type': generate_analysis_entry(analysis_result=TYPE_RESULT)},
        )
        insert_test_fo(
            backend_db,
            'uid2',
            file_name='test_data_file.bin',
            analysis={'file_type': generate_analysis_entry(analysis_result=TYPE_RESULT)},
            parent_fw='uid',
        )

        response_false = self.test_client.get('/rest/analysis/uid/file_type?recursive_summary=false')
        assert response_false.status_code == HTTPStatus.OK
        assert 'analysis' in response_false.json
        assert 'recursive_summary' in response_false.json
        assert response_false.json['recursive_summary'] == {}

        response_true = self.test_client.get('/rest/analysis/uid/file_type?recursive_summary=true')
        assert response_true.status_code == HTTPStatus.OK
        assert 'analysis' in response_true.json
        assert 'recursive_summary' in response_true.json
        assert response_true.json['recursive_summary'] != {}

    def test_rest_put_analysis(self, backend_db, monkeypatch):
        insert_test_fo(backend_db, 'uid')

        monkeypatch.setattr(
            'intercom.front_end_binding.InterComFrontEndBinding.get_available_analysis_plugins',
            lambda _: ['file_type', 'some_other_plugin'],
        )
        monkeypatch.setattr(
            'intercom.front_end_binding.InterComFrontEndBinding.add_single_file_task',
            lambda _, __: True,
        )

        response = self.test_client.put('/rest/analysis/uid/file_type')
        assert response.status_code == HTTPStatus.OK
        assert response.json['success'] is True

    def test_rest_put_analysis_no_file(self, monkeypatch):
        monkeypatch.setattr(
            'intercom.front_end_binding.InterComFrontEndBinding.get_available_analysis_plugins',
            lambda _: ['file_type'],
        )

        response = self.test_client.put('/rest/analysis/unknown_uid/file_type')
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert 'error_message' in response.json
        assert 'No file object with UID' in response.json['error_message']

    def test_rest_put_analysis_invalid_plugin(self, backend_db, monkeypatch):
        insert_test_fo(backend_db, 'uid')
        monkeypatch.setattr(
            'intercom.front_end_binding.InterComFrontEndBinding.get_available_analysis_plugins',
            lambda _: ['file_type'],
        )

        unknown_plugin = 'unknown_plugin'
        response = self.test_client.put(f'/rest/analysis/uid/{unknown_plugin}')
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert 'error_message' in response.json
        assert f'Analysis plugin "{unknown_plugin}" not found' in response.json['error_message']

    def test_rest_put_analysis_force(self, backend_db, monkeypatch):
        insert_test_fo(backend_db, 'uid')
        monkeypatch.setattr(
            'intercom.front_end_binding.InterComFrontEndBinding.get_available_analysis_plugins',
            lambda _: ['file_type'],
        )
        monkeypatch.setattr(
            'intercom.front_end_binding.InterComFrontEndBinding.add_single_file_task',
            lambda _, fo: fo.force_update is True,
        )

        response = self.test_client.put('/rest/analysis/uid/file_type?force=true')
        assert response.status_code == HTTPStatus.OK
        assert response.json['success'] is True

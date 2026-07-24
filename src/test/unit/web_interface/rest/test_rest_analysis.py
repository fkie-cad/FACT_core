import pytest

from test.common_helper import TEST_FW, CommonDatabaseMock
from test.unit.conftest import CommonIntercomMock

PLUGIN = 'existing_plugin'
UID = 'existing_uid'
ANALYSIS_RESULT = {'result_key': 'result_value'}


class AnalysisDBMock(CommonDatabaseMock):
    @staticmethod
    def get_analysis(uid, plugin):
        if uid == UID and plugin == PLUGIN:
            return ANALYSIS_RESULT
        return None

    @staticmethod
    def get_object(uid):
        if uid == TEST_FW.uid:
            TEST_FW.processed_analysis = {PLUGIN: ANALYSIS_RESULT}
            return TEST_FW
        return None

    def exists(self, uid):
        return uid == UID


class AnalysisIntercomMock(CommonIntercomMock):
    def get_available_analysis_plugins(self):
        return [
            PLUGIN,
        ]

    def add_single_file_task(self, file_object):
        return file_object.uid == TEST_FW.uid


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=AnalysisDBMock, intercom_mock_class=AnalysisIntercomMock)
class TestRestAnalysis:
    def test_get_analysis(self, test_client):
        result = test_client.get(f'/rest/analysis/{UID}/{PLUGIN}').json

        assert 'analysis' in result
        assert result['analysis'] == ANALYSIS_RESULT

    def test_get_analysis_unknown_file(self, test_client):
        result = test_client.get(f'/rest/analysis/unknown_uid/{PLUGIN}').json

        assert 'analysis' not in result
        assert 'error_message' in result
        assert 'No file object with UID' in result['error_message']

    def test_get_analysis_unknown_analysis(self, test_client):
        result = test_client.get(f'/rest/analysis/{UID}/unknown_plugin').json

        assert 'analysis' not in result
        assert 'error_message' in result
        assert '"unknown_plugin" not found' in result['error_message']

    def test_put_analysis(self, test_client):
        result = test_client.put(f'/rest/analysis/{TEST_FW.uid}/{PLUGIN}').json

        assert 'success' in result, 'missing field in result'
        assert result['success'], 'put should be successful'

    def test_put_analysis_unknown_file(self, test_client):
        bad_uid = 'nosuch_uid'
        result = test_client.put(f'/rest/analysis/{bad_uid}/{PLUGIN}').json

        assert 'error_message' in result, 'missing error message'
        assert 'No file' in result['error_message'], 'misformed error message'

    def test_put_analysis_unknown_plugin(self, test_client):
        bad_plugin = 'nosuch_plugin'
        result = test_client.put(f'/rest/analysis/{TEST_FW.uid}/{bad_plugin}').json

        assert 'error_message' in result, 'missing error message'
        assert f'"{bad_plugin}" not found' in result['error_message'], 'misformed error message'

    def test_put_analysis_force_update(self, test_client):
        result = test_client.put(f'/rest/analysis/{TEST_FW.uid}/{PLUGIN}?force=true').json

        assert 'success' in result, 'missing field in result'
        assert result['success'], 'put should be successful'

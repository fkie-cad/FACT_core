import pytest

from tests.common_helper import CommonDatabaseMock

PLUGIN = 'existing_plugin'
UID = 'existing_uid'
ANALYSIS_RESULT = {'result_key': 'result_value'}


class StatisticDbViewerMock(CommonDatabaseMock):
    @staticmethod
    def get_analysis(uid, plugin):
        if uid == UID and plugin == PLUGIN:
            return ANALYSIS_RESULT
        return None

    def exists(self, uid):
        return uid == UID


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=StatisticDbViewerMock)
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

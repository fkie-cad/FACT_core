import pytest

from tests.common_helper import CommonDatabaseMock

BACKEND_STATS = {'system': {'cpu_percentage': 13.37}, 'analysis': {'current_analyses': [None, None]}}


class StatisticDbViewerMock(CommonDatabaseMock):
    down = None

    def get_statistic(self, identifier):
        return None if self.down or identifier != 'backend' else BACKEND_STATS


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=StatisticDbViewerMock)
class TestRestFirmware:
    def test_empty_uid(self, test_client):
        StatisticDbViewerMock.down = False
        result = test_client.get('/rest/status').json

        assert result['status'] == 0
        assert result['system_status'] == {'backend': BACKEND_STATS, 'database': None, 'frontend': None}

    def test_empty_result(self, test_client):
        StatisticDbViewerMock.down = True
        result = test_client.get('/rest/status').json
        assert 'Cannot get FACT component status' in result['error_message']

import pytest

from test.common_helper import CommonDatabaseMock

BACKEND_STATS = {'system': {'cpu_percentage': 13.37}, 'analysis': {'current_analyses': [None, None]}}


class StatisticDbViewerMock(CommonDatabaseMock):
    def get_statistic(self, identifier):
        return BACKEND_STATS if identifier == 'backend' else None


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=StatisticDbViewerMock)
def test_empty_uid(test_client):
    result = test_client.get('/rest/status').json
    assert result['status'] == 0
    assert result['system_status'] == {'backend': BACKEND_STATS, 'database': None, 'frontend': None}


class ComponentsDownMock(CommonDatabaseMock):
    def get_statistic(self, identifier):
        return None


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=ComponentsDownMock)
def test_empty_result(test_client):
    result = test_client.get('/rest/status').json
    assert 'Cannot get FACT component status' in result['error_message']

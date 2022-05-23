# pylint: disable=no-self-use
import pytest

from test.common_helper import CommonDatabaseMock

BACKEND_STATS = {
    'system': {'cpu_percentage': 13.37},
    'analysis': {'current_analyses': [None, None]}
}


class StatisticDbViewerMock(CommonDatabaseMock):
    down = None

    def get_statistic(self, identifier):
        return None if self.down or identifier != 'backend' else BACKEND_STATS


@pytest.mark.DatabaseMockClass(lambda: StatisticDbViewerMock)
def test_empty_uid(test_client):
    StatisticDbViewerMock.down = False
    result = test_client.get('/rest/status').json

    assert result['status'] == 0
    assert result['system_status'] == {
        'backend': BACKEND_STATS,
        'database': None,
        'frontend': None
    }


@pytest.mark.DatabaseMockClass(lambda: StatisticDbViewerMock)
def test_empty_result(test_client):
    StatisticDbViewerMock.down = True
    result = test_client.get('/rest/status').json
    assert 'Cannot get FACT component status' in result['error_message']

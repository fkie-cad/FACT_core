from test.common_helper import CommonDatabaseMock

from ..base import WebInterfaceTest

BACKEND_STATS = {'system': {'cpu_percentage': 13.37}, 'analysis': {'current_analyses': [None, None]}}


class StatisticDbViewerMock(CommonDatabaseMock):
    down = None

    def get_statistic(self, identifier):
        return None if self.down or identifier != 'backend' else BACKEND_STATS


class TestRestFirmware(WebInterfaceTest):
    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=StatisticDbViewerMock)

    def test_empty_uid(self):
        StatisticDbViewerMock.down = False
        result = self.test_client.get('/rest/status').json

        assert result['status'] == 0
        assert result['system_status'] == {'backend': BACKEND_STATS, 'database': None, 'frontend': None}

    def test_empty_result(self):
        StatisticDbViewerMock.down = True
        result = self.test_client.get('/rest/status').json
        assert 'Cannot get FACT component status' in result['error_message']

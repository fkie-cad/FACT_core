import pytest

from test.unit.conftest import StatusInterfaceMock

BACKEND_STATS = {'system': {'cpu_percentage': 13.37}, 'analysis': {'current_analyses': [None, None]}}


class ComponentStatusMock(StatusInterfaceMock):
    down = None

    def get_component_status(self, component):
        return None if self.down or component != 'backend' else BACKEND_STATS


@pytest.mark.WebInterfaceUnitTestConfig(status_mock_class=ComponentStatusMock)
class TestRestStatus:
    def test_empty_uid(self, test_client):
        ComponentStatusMock.down = False
        result = test_client.get('/rest/status').json

        assert result['status'] == 0
        assert result['system_status'] == {'backend': BACKEND_STATS, 'database': None, 'frontend': None}

    def test_empty_result(self, test_client):
        ComponentStatusMock.down = True
        result = test_client.get('/rest/status').json
        assert 'Cannot get FACT component status' in result['error_message']

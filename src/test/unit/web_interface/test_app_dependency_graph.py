# pylint: disable=wrong-import-order
import pytest

from test.common_helper import TEST_FW, CommonDatabaseMock
from test.unit.web_interface.test_dependency_graph import entry_1, entry_2


class DbMock(CommonDatabaseMock):
    @staticmethod
    def get_data_for_dependency_graph(uid):
        if uid == 'testgraph':
            return [entry_1, entry_2]
        return []


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
def test_app_dependency_graph(test_client):
    result = test_client.get(f'/dependency-graph/testgraph/{TEST_FW.uid}')
    assert b'<strong>UID:</strong> testgraph' in result.data
    assert (
        b'Error: Graph could not be rendered. The file chosen as root must contain a filesystem with binaries.'
        not in result.data
    )
    assert b'Warning: Elf analysis plugin result is missing for 1 files' in result.data
    result_error = test_client.get('/dependency-graph/1234567/567879')
    assert (
        b'Error: Graph could not be rendered. The file chosen as root must contain a filesystem with binaries.'
        in result_error.data
    )

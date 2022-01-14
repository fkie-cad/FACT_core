# pylint: disable=wrong-import-order
from storage_postgresql.db_interface_frontend import DependencyGraphResult
from test.common_helper import CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest


class DbMock(CommonDatabaseMock):

    @staticmethod
    def get_data_for_dependency_graph(uid):
        if uid == 'testgraph':
            return [
                DependencyGraphResult('1234567', 'file one', 'application/x-executable', 'test text', None),
                DependencyGraphResult('7654321', 'file two', 'application/x-executable', 'test text', ['file one']),
            ]
        return []


class TestAppDependencyGraph(WebInterfaceTest):

    def setup(self, *_, **__):
        super().setup(db_mock=DbMock)

    def test_app_dependency_graph(self):
        result = self.test_client.get('/dependency-graph/testgraph')
        assert b'<strong>UID:</strong> testgraph' in result.data
        assert b'Error: Graph could not be rendered. The file chosen as root must contain a filesystem with binaries.' not in result.data
        assert b'Warning: Elf analysis plugin result is missing for 1 files' in result.data
        result_error = self.test_client.get('/dependency-graph/1234567')
        assert b'Error: Graph could not be rendered. The file chosen as root must contain a filesystem with binaries.' in result_error.data

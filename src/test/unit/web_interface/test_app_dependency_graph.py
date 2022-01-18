# pylint: disable=wrong-import-order
from test.common_helper import CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest
from web_interface.components.dependency_graph import DepGraphData


class DbMock(CommonDatabaseMock):

    @staticmethod
    def get_data_for_dependency_graph(uid):
        if uid == 'testgraph':
            return [
                DepGraphData('1234567', 'file one', 'application/x-executable', 'test text', None),
                DepGraphData('7654321', 'file two', 'application/x-executable', 'test text', ['file one']),
            ]
        return []


class TestAppDependencyGraph(WebInterfaceTest):

    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)

    def test_app_dependency_graph(self):
        result = self.test_client.get('/dependency-graph/testgraph')
        assert b'<strong>UID:</strong> testgraph' in result.data
        assert b'Error: Graph could not be rendered. The file chosen as root must contain a filesystem with binaries.' not in result.data
        assert b'Warning: Elf analysis plugin result is missing for 1 files' in result.data
        result_error = self.test_client.get('/dependency-graph/1234567')
        assert b'Error: Graph could not be rendered. The file chosen as root must contain a filesystem with binaries.' in result_error.data

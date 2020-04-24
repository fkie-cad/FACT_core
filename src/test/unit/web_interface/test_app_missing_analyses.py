from test.common_helper import DatabaseMock
from test.unit.web_interface.base import WebInterfaceTest


class MissingAnalysesDbMock(DatabaseMock):
    result = None

    def find_missing_files(self):
        return self.result

    def find_missing_analyses(self):
        return self.result


class TestAppMissingAnalyses(WebInterfaceTest):
    def setUp(self, db_mock=None):
        super().setUp(db_mock=MissingAnalysesDbMock)

    def test_app_no_missing_analyses(self):
        MissingAnalysesDbMock.result = {}
        content = self.test_client.get('/admin/missing_analyses').data.decode()
        assert 'No missing files found' in content
        assert 'No missing analyses found' in content

    def test_app_missing_analyses(self):
        MissingAnalysesDbMock.result = {'parent_uid': {'child_uid1', 'child_uid2'}}
        content = self.test_client.get('/admin/missing_analyses').data.decode()
        assert '2 Missing Analyses' in content
        assert '2 Missing Files' in content
        assert 'parent_uid' in content
        assert 'child_uid1' in content and 'child_uid2' in content

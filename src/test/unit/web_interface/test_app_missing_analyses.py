from test.common_helper import CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest


class DbMock(CommonDatabaseMock):
    result = None

    def find_missing_analyses(self):
        return self.result

    def find_failed_analyses(self):
        return self.result


class TestAppMissingAnalyses(WebInterfaceTest):

    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)

    def test_app_no_missing_analyses(self):
        DbMock.result = {}
        content = self.test_client.get('/admin/missing_analyses').data.decode()
        assert 'Missing Analyses: No entries found' in content
        assert 'Failed Analyses: No entries found' in content

    def test_app_missing_analyses(self):
        DbMock.result = {'parent_uid': {'child_uid1', 'child_uid2'}}
        content = self.test_client.get('/admin/missing_analyses').data.decode()
        assert 'Missing Analyses: 2' in content
        assert 'Failed Analyses: 2' in content
        assert 'parent_uid' in content
        assert 'child_uid1' in content and 'child_uid2' in content

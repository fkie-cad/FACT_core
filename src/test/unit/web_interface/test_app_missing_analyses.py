import pytest

from test.common_helper import CommonDatabaseMock


class DbMock(CommonDatabaseMock):
    result = None

    def find_missing_analyses(self):
        return self.result

    def find_failed_analyses(self):
        return self.result


@pytest.mark.WebInterfaceUnitTestConfig(dict(database_mock_class=DbMock))
class TestAppMissingAnalyses:
    def test_app_no_missing_analyses(self, test_client):
        DbMock.result = {}
        content = test_client.get('/admin/missing_analyses').data.decode()
        assert 'Missing Analyses: No entries found' in content
        assert 'Failed Analyses: No entries found' in content

    def test_app_missing_analyses(self, test_client):
        DbMock.result = {'parent_uid': {'child_uid1', 'child_uid2'}}
        content = test_client.get('/admin/missing_analyses').data.decode()
        assert 'Missing Analyses: 2' in content
        assert 'Failed Analyses: 2' in content
        assert 'parent_uid' in content
        assert 'child_uid1' in content and 'child_uid2' in content

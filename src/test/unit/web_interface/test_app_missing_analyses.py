# pylint: disable=no-self-use
import pytest

from test.common_helper import CommonDatabaseMock


def get_db_mock_with_result(result):
    class DbMock(CommonDatabaseMock):
        def find_missing_analyses(self):
            return result

        def find_failed_analyses(self):
            return result

    return DbMock


@pytest.mark.DatabaseMockClass(lambda: get_db_mock_with_result({}))
def test_app_no_missing_analyses(test_client):
    content = test_client.get('/admin/missing_analyses').data.decode()
    assert 'Missing Analyses: No entries found' in content
    assert 'Failed Analyses: No entries found' in content


@pytest.mark.DatabaseMockClass(lambda: get_db_mock_with_result({'parent_uid': {'child_uid1', 'child_uid2'}}))
def test_app_missing_analyses(test_client):
    content = test_client.get('/admin/missing_analyses').data.decode()
    assert 'Missing Analyses: 2' in content
    assert 'Failed Analyses: 2' in content
    assert 'parent_uid' in content
    assert 'child_uid1' in content and 'child_uid2' in content

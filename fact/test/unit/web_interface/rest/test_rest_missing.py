import pytest

from fact.test.common_helper import CommonDatabaseMock


class DbMock(CommonDatabaseMock):
    @staticmethod
    def find_missing_analyses():
        return {'root_fw_uid': ['missing_child_uid']}

    @staticmethod
    def find_failed_analyses():
        return {'plugin': ['missing_child_uid']}


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
def test_missing(test_client):
    result = test_client.get('/rest/missing').json

    assert 'missing_analyses' in result
    assert result['missing_analyses'] == {'root_fw_uid': ['missing_child_uid']}

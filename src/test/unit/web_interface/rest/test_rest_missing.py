from test.common_helper import CommonDatabaseMock

from ..base import WebInterfaceTest


class DbMock(CommonDatabaseMock):

    @staticmethod
    def find_missing_analyses():
        return {'root_fw_uid': ['missing_child_uid']}

    @staticmethod
    def find_failed_analyses():
        return {'plugin': ['missing_child_uid']}


class TestRestFirmware(WebInterfaceTest):

    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)

    def test_missing(self):
        result = self.test_client.get('/rest/missing').json

        assert 'missing_analyses' in result
        assert result['missing_analyses'] == {'root_fw_uid': ['missing_child_uid']}

from time import time

from test.common_helper import CommonDatabaseMock
from test.unit.web_interface.base import WebInterfaceTest


class DbMock(CommonDatabaseMock):
    result = None

    def get_statistic(self, identifier):
        return self.result if identifier == 'general' else None


class TestShowStatistic(WebInterfaceTest):

    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(db_mock=DbMock)

    def test_no_stats_available(self):
        DbMock.result = None
        rv = self.test_client.get('/statistic')
        assert b'General' not in rv.data
        assert b'<strong>No statistics available!</strong>' in rv.data

    def test_stats_available(self):
        DbMock.result = {
            'number_of_firmwares': 1,
            'total_firmware_size': 1,
            'average_firmware_size': 1,
            'number_of_unique_files': 1,
            'total_file_size': 10,
            'average_file_size': 10,
            'creation_time': time(),
            'benchmark': 1.1,
        }
        page_content = self.test_client.get('/statistic').data.decode()
        assert 'General' in page_content
        assert '>10.00 Byte<' in page_content

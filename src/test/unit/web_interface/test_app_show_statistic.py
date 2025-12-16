from time import time

import pytest

from test.common_helper import CommonDatabaseMock


class DbMock(CommonDatabaseMock):
    result = None

    def get_statistic(self, identifier):
        return self.result if identifier == 'general' else None


@pytest.mark.WebInterfaceUnitTestConfig(database_mock_class=DbMock)
class TestShowStatistic:
    def test_no_stats_available(self, test_client):
        DbMock.result = None
        rv = test_client.get('/statistic')
        assert b'General' not in rv.data
        assert b'<strong>No statistics available!</strong>' in rv.data

    def test_stats_available(self, test_client):
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
        page_content = test_client.get('/statistic').data.decode()
        assert 'General' in page_content
        assert '>10 bytes<' in page_content

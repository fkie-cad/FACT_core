# pylint: disable=no-self-use
from time import time

import pytest

from test.common_helper import CommonDatabaseMock


def get_db_mock_with_result(result):
    class DbMock(CommonDatabaseMock):
        def get_statistic(self, identifier):
            return result if identifier == 'general' else None

    return DbMock


@pytest.mark.DatabaseMockClass(lambda: get_db_mock_with_result(None))
def test_no_stats_available(test_client):
    rv = test_client.get('/statistic')
    assert b'General' not in rv.data
    assert b'<strong>No statistics available!</strong>' in rv.data


@pytest.mark.DatabaseMockClass(
    lambda: get_db_mock_with_result(
        {
            'number_of_firmwares': 1,
            'total_firmware_size': 1,
            'average_firmware_size': 1,
            'number_of_unique_files': 1,
            'total_file_size': 10,
            'average_file_size': 10,
            'creation_time': time(),
            'benchmark': 1.1,
        }
    )
)
def test_stats_available(test_client):
    page_content = test_client.get('/statistic').data.decode()
    assert 'General' in page_content
    assert '>10.00 Byte<' in page_content

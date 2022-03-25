# pylint: disable=wrong-import-order
import pytest
from pathlib import Path

import helperFunctions.fileSystem
from test.common_helper import CommonIntercomMock


class MockIntercom(CommonIntercomMock):
    @staticmethod
    def get_backend_logs():
        return ['String1', 'String2', 'String3']


@pytest.mark.intercom_mock(lambda: MockIntercom)
@pytest.mark.cfg_defaults(
    {
        "logging": {
            "logfile": 'NonExistentFile',
        },
    }
)
def test_backend_available(test_client):
    rv = test_client.get('/admin/logs')
    assert b'String1' in rv.data


@pytest.mark.intercom_mock(lambda: MockIntercom)
@pytest.mark.cfg_defaults(
    {
        "logging": {
            "logfile": str(Path(helperFunctions.fileSystem.get_src_dir()) / 'test/data/logs'),
        },
    }
)
def test_frontend_logs(test_client):
    rv = test_client.get('/admin/logs')
    assert b'Frontend_test' in rv.data

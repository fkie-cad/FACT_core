from pathlib import Path

import pytest

import fact.helperFunctions.fileSystem
from fact.test.unit.conftest import CommonIntercomMock


class MockIntercom(CommonIntercomMock):
    @staticmethod
    def get_backend_logs():
        return ['String1', 'String2', 'String3']


@pytest.mark.WebInterfaceUnitTestConfig(intercom_mock_class=MockIntercom)
class TestShowLogs:
    @pytest.mark.frontend_config_overwrite(
        {
            'logging': {
                'file_backend': 'NonExistentFile',
            }
        }
    )
    def test_backend_available(self, test_client):
        rv = test_client.get('/admin/logs')

        assert b'String1' in rv.data

    @pytest.mark.common_config_overwrite(
        {
            'logging': {
                'file_frontend': str(Path(fact.helperFunctions.fileSystem.get_src_dir()) / 'test/data/logs_frontend')
            }
        }
    )
    def test_frontend_logs(self, test_client):
        rv = test_client.get('/admin/logs')
        assert b'Frontend_test' in rv.data

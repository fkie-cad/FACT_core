# pylint: disable=wrong-import-order
from pathlib import Path

import pytest

import helperFunctions.fileSystem
from test.common_helper import CommonIntercomMock
from test.unit.web_interface.base import WebInterfaceTest


class MockIntercom(CommonIntercomMock):
    @staticmethod
    def get_backend_logs():
        return ['String1', 'String2', 'String3']


class TestShowLogs(WebInterfaceTest):
    @classmethod
    def setup_class(cls, *_, **__):
        super().setup_class(intercom_mock=MockIntercom)

    @pytest.mark.cfg_defaults(
        {
            'logging': {
                'logfile': 'NonExistentFile',
            }
        }
    )
    def test_backend_available(self):
        rv = self.test_client.get('/admin/logs')
        assert b'String1' in rv.data

    @pytest.mark.cfg_defaults(
        {
            'logging': {
                'logfile': str(Path(helperFunctions.fileSystem.get_src_dir()) / 'test/data/logs'),
            }
        }
    )
    def test_frontend_logs(self):
        rv = self.test_client.get('/admin/logs')
        assert b'Frontend_test' in rv.data

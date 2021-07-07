from pathlib import Path

import helperFunctions.fileSystem
from test.unit.web_interface.base import WebInterfaceTest


class IntercomMock:
    @staticmethod
    def get_backend_logs():
        return ['String1', 'String2', 'String3']

    def shutdown(self):
        pass


class TestShowStatistic(WebInterfaceTest):
    def setUp(self, db_mock=None):
        super().setUp(db_mock=IntercomMock)
        self.config['Logging']['logFile'] = 'NonExistentFile'

    def test_logs_available(self):
        rv = self.test_client.get('/admin/logs')
        assert b'String1' in rv.data

    def test_frontend_logs(self):
        self.config['Logging']['logFile'] = str(Path(helperFunctions.fileSystem.get_src_dir()) / 'test/data/logs')
        rv = self.test_client.get('/admin/logs')
        assert b'Frontend_test' in rv.data

from pathlib import Path

import helperFunctions.fileSystem
from test.unit.web_interface.base import WebInterfaceTest


class IntercomMock:
    @staticmethod
    def get_backend_logs():
        return ['String1', 'String2', 'String3']

    def shutdown(self):
        pass


class TestShowLogs(WebInterfaceTest):
    def setUp(self, db_mock=None):
        super().setUp(db_mock=IntercomMock)

    def test_backend_available(self):
        self.config['Logging']['logFile'] = 'NonExistentFile'
        rv = self.test_client.get('/admin/logs')
        assert b'String1' in rv.data

    def test_frontend_logs(self):
        self.config['Logging']['logFile'] = str(Path(helperFunctions.fileSystem.get_src_dir()) / 'test/data/logs')
        rv = self.test_client.get('/admin/logs')
        assert b'Frontend_test' in rv.data

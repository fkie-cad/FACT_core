from storage.db_interface_backend import BackEndDbInterface
from test.acceptance.base import TestAcceptanceBase


class TestAcceptanceAdvancedSearch(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend_interface = BackEndDbInterface(self.config)

    def tearDown(self):
        self.db_backend_interface.shutdown()
        self._stop_backend()
        super().tearDown()

    def test_advanced_search_get(self):
        rv = self.test_client.get('/database/binary_search')
        assert b'<h2>Binary Pattern Search</h2>' in rv.data

    def test_binary_pattern_search(self):
        self.db_backend_interface.add_firmware(self.test_fw_a)

    def test_binary_pattern_search_only_firmware(self):
        self.db_backend_interface.add_firmware(self.test_fw_a)

from test.common_helper import create_test_firmware
from test.acceptance.auth_base import TestAuthenticatedAcceptanceBase
from storage.db_interface_backend import BackEndDbInterface


class TestAcceptanceNormalSearch(TestAuthenticatedAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        # self.db_backend_interface = BackEndDbInterface(self.config)
        # self.test_fw = create_test_firmware(device_name='test_fw')
        # self.db_backend_interface.add_firmware(self.test_fw)

    def tearDown(self):
        # self.db_backend_interface.shutdown()
        self._stop_backend()
        super().tearDown()

    def test_redirection(self):
        response = self.test_client.get('/', follow_redirects=False)
        self.assertIn(b'Redirecting', response.data, 'no redirection taking place')

    def test_show_login_page(self):
        response = self.test_client.get('/', follow_redirects=True)
        self.assertIn(b'Remember Me', response.data, 'no authorization required')

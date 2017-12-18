from test.common_helper import create_test_firmware
from test.acceptance.base import TestAcceptanceBase
from storage.db_interface_backend import BackEndDbInterface


class TestAcceptanceNormalSearch(TestAcceptanceBase):

    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend_interface = BackEndDbInterface(self.config)
        self.test_fw = create_test_firmware(device_name='test_fw')
        self.db_backend_interface.add_firmware(self.test_fw)

    def tearDown(self):
        self.db_backend_interface.shutdown()
        self._stop_backend()
        super().tearDown()

    def _show_database_access_page(self):
        rv = self.test_client.get('/database')
        self.assertIn(b'<b>Search Database</b>', rv.data, 'database access page not rendered correctly')

    def _show_search_get(self):
        rv = self.test_client.get('/database/search')
        self.assertIn(b'<h2>Search Firmware Database</h2>', rv.data, 'search page not rendered correctly')

    def _show_browse_db(self):
        rv = self.test_client.get('/database/browse')
        self.assertIn(self.test_fw.get_uid().encode(), rv.data, 'test firmware not found in browse database')

    def _show_search_post(self):
        data = {
            'device_class_dropdown': '',
            'file_name': '',
            'vendor': '',
            'device_name': '',
            'version': '',
            'release_date': '',
            'hash_value': ''
        }
        rv = self.test_client.post('/database/search', content_type='multipart/form-data', follow_redirects=True, data=data)
        self.assertIn(self.test_fw.get_uid().encode(), rv.data, 'test firmware not found in empty search')
        data['file_name'] = self.test_fw.file_name
        data['vendor'] = self.test_fw.vendor
        rv = self.test_client.post('/database/search', content_type='multipart/form-data', follow_redirects=True, data=data)
        self.assertIn(self.test_fw.get_uid().encode(), rv.data, 'test firmware not found in specific search')

    def _show_quick_search(self):
        rv = self.test_client.get('/database/quick_search?search_term=test_fw', follow_redirects=True)
        self.assertIn(self.test_fw.get_uid().encode(), rv.data, 'test firmware not found in specific search')

    def test_search(self):
        self._show_database_access_page()
        self._show_browse_db()
        self._show_search_get()
        self._show_search_post()
        self._show_quick_search()

from storage.db_interface_backend import BackendDbInterface
from test.acceptance.base import TestAcceptanceBase  # pylint: disable=wrong-import-order
from test.common_helper import create_test_firmware  # pylint: disable=wrong-import-order


class TestAcceptanceNormalSearch(TestAcceptanceBase):
    def setUp(self):
        super().setUp()
        self._start_backend()
        self.db_backend_interface = BackendDbInterface(self.config)
        self.test_fw = create_test_firmware(device_name='test_fw')
        self.test_fw.release_date = '2001-02-03'
        self.db_backend_interface.add_object(self.test_fw)

    def tearDown(self):
        self._stop_backend()
        super().tearDown()

    def _show_search_get(self):
        rv = self.test_client.get('/database/search')
        assert b'<h3 class="mb-3">Search Firmware Database</h3>' in rv.data, 'search page not rendered correctly'

    def _show_browse_db(self):
        rv = self.test_client.get('/database/browse')
        assert self.test_fw.uid.encode() in rv.data, 'test firmware not found in browse database'

    def _show_browse_compare(self):
        rv = self.test_client.get('/database/browse_compare')
        assert '200' in rv.status, 'compare browsing site offline'

    def _show_search_post(self):
        data = {
            'device_class_dropdown': '',
            'file_name': '',
            'vendor': '',
            'device_name': '',
            'version': '',
            'release_date': '',
            'hash_value': '',
        }
        rv = self.test_client.post(
            '/database/search', content_type='multipart/form-data', follow_redirects=True, data=data
        )
        assert self.test_fw.uid.encode() in rv.data, 'test firmware not found in empty search'
        data['file_name'] = self.test_fw.file_name
        data['vendor'] = self.test_fw.vendor
        rv = self.test_client.post(
            '/database/search', content_type='multipart/form-data', follow_redirects=True, data=data
        )
        assert self.test_fw.uid.encode() in rv.data, 'test firmware not found in specific search'

    def _show_quick_search(self):
        rv = self.test_client.get('/database/quick_search?search_term=test_fw', follow_redirects=True)
        assert self.test_fw.uid.encode() in rv.data, 'test firmware not found in specific search'

    def _search_date(self):
        rv = self.test_client.get('/database/browse?date=February 2001', follow_redirects=True)
        assert self.test_fw.uid.encode() in rv.data, 'date search does not work'
        rv = self.test_client.get('/database/browse?date=February 2002', follow_redirects=True)
        assert self.test_fw.uid.encode() not in rv.data, 'date search does not work'

    def test_search(self):
        self._show_browse_db()
        self._show_browse_compare()
        self._show_search_get()
        self._show_search_post()
        self._show_quick_search()
        self._search_date()

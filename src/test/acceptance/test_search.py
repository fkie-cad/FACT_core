import pytest

from test.common_helper import create_test_firmware


@pytest.fixture(autouse=True)
def _autouse_intercom_backend_binding(intercom_backend_binding):  # noqa: ARG001
    pass


test_fw = create_test_firmware(device_name='test_fw')
test_fw.release_date = '2001-02-03'


@pytest.fixture(autouse=True)
def _auto_insert_firmware(backend_db):
    backend_db.add_object(test_fw)


class TestAcceptanceNormalSearch:
    def _show_search_get(self, test_client):
        rv = test_client.get('/database/search')
        assert b'<h3 class="mb-3">Search Firmware Database</h3>' in rv.data, 'search page not rendered correctly'

    def _show_browse_db(self, test_client):
        rv = test_client.get('/database/browse')
        assert test_fw.uid.encode() in rv.data, 'test firmware not found in browse database'

    def _show_browse_comparisons(self, test_client):
        rv = test_client.get('/database/browse_comparisons')
        assert '200' in rv.status, 'comparison browsing site offline'

    def _show_search_post(self, test_client):
        data = {
            'device_class_dropdown': '',
            'file_name': '',
            'vendor': '',
            'device_name': '',
            'version': '',
            'release_date': '',
            'hash_value': '',
        }
        rv = test_client.post('/database/search', content_type='multipart/form-data', follow_redirects=True, data=data)
        assert test_fw.uid.encode() in rv.data, 'test firmware not found in empty search'
        data['file_name'] = test_fw.file_name
        data['vendor'] = test_fw.vendor
        rv = test_client.post('/database/search', content_type='multipart/form-data', follow_redirects=True, data=data)
        assert test_fw.uid.encode() in rv.data, 'test firmware not found in specific search'

    def _show_quick_search(self, test_client):
        rv = test_client.get('/database/quick_search?search_term=test_fw', follow_redirects=True)
        assert test_fw.uid.encode() in rv.data, 'test firmware not found in specific search'

    def _search_date(self, test_client):
        rv = test_client.get('/database/browse?date=February 2001', follow_redirects=True)
        assert test_fw.uid.encode() in rv.data, 'date search does not work'
        rv = test_client.get('/database/browse?date=February 2002', follow_redirects=True)
        assert test_fw.uid.encode() not in rv.data, 'date search does not work'

    def test_search(self, test_client):
        self._show_browse_db(test_client)
        self._show_browse_comparisons(test_client)
        self._show_search_get(test_client)
        self._show_search_post(test_client)
        self._show_quick_search(test_client)
        self._search_date(test_client)

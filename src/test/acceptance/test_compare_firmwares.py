# pylint: disable=no-self-use
import pytest

from test.common_helper import upload_test_firmware


@pytest.mark.usefixtures('backend_services')
class TestAcceptanceCompareFirmwares:

    NUMBER_OF_FILES_TO_ANALYZE = 8
    NUMBER_OF_PLUGINS = 2

    def _add_firmwares_to_compare(self, test_client, test_fw_a, test_fw_c):
        rv = test_client.get(f'/analysis/{test_fw_a.uid}')
        assert test_fw_a.uid in rv.data.decode(), ''
        rv = test_client.get(f'/comparison/add/{test_fw_a.uid}', follow_redirects=True)
        assert 'Firmware Selected for Comparison' in rv.data.decode()

        rv = test_client.get(f'/analysis/{test_fw_c.uid}')
        assert test_fw_c.uid in rv.data.decode()
        assert test_fw_c.name in rv.data.decode()
        rv = test_client.get(f'/comparison/add/{test_fw_c.uid}', follow_redirects=True)
        assert 'Remove All' in rv.data.decode()

    def _start_compare(self, test_client):
        rv = test_client.get('/compare', follow_redirects=True)
        assert b'Your compare task is in progress.' in rv.data, 'compare wait page not displayed correctly'

    def _show_comparison_results(self, test_client, test_fw_a, test_fw_c):
        rv = test_client.get(f'/compare/{test_fw_a.uid};{test_fw_c.uid}')
        assert test_fw_a.name.encode() in rv.data, 'test firmware a comparison not displayed correctly'
        assert test_fw_c.name.encode() in rv.data, 'test firmware b comparison not displayed correctly'
        assert b'File Coverage' in rv.data, 'comparison page not displayed correctly'

    def _show_home_page(self, test_client):
        rv = test_client.get('/')
        assert b'Latest Comparisons' in rv.data, 'latest comparisons not displayed on "home"'

    def _show_compare_browse(self, test_client, test_fw_a):
        rv = test_client.get('/database/browse_compare')
        assert test_fw_a.name.encode() in rv.data, 'no compare result shown in browse'

    def _show_analysis_without_compare_list(self, test_client, test_fw_a):
        rv = test_client.get(f'/analysis/{test_fw_a.uid}')
        assert b'Show list of known comparisons' not in rv.data

    def _show_analysis_with_compare_list(self, test_client, test_fw_a):
        rv = test_client.get(f'/analysis/{test_fw_a.uid}')
        assert b'Show list of known comparisons' in rv.data

    def test_compare_firmwares(self, test_client, analysis_finished_event, compare_finished_event, test_fw_a, test_fw_c):
        upload_test_firmware(test_client, test_fw_a)
        upload_test_firmware(test_client, test_fw_c)

        analysis_finished_event.wait(timeout=20)
        self._show_analysis_without_compare_list(test_client, test_fw_a)
        self._add_firmwares_to_compare(test_client, test_fw_a, test_fw_c)
        self._start_compare(test_client)
        compare_finished_event.wait(timeout=20)
        self._show_comparison_results(test_client, test_fw_a, test_fw_c)
        self._show_home_page(test_client)
        self._show_compare_browse(test_client, test_fw_a)
        self._show_analysis_with_compare_list(test_client, test_fw_a)

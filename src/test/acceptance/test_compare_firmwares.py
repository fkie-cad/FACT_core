from test.acceptance.base_full_start import TestAcceptanceBaseFullStart


class TestAcceptanceCompareFirmwares(TestAcceptanceBaseFullStart):

    NUMBER_OF_FILES_TO_ANALYZE = 8
    NUMBER_OF_PLUGINS = 2

    def _add_firmwares_to_compare(self):
        rv = self.test_client.get(f'/analysis/{self.test_fw_a.uid}')
        assert self.test_fw_a.uid in rv.data.decode()
        rv = self.test_client.get(f'/comparison/add/{self.test_fw_a.uid}', follow_redirects=True)
        assert 'Firmware Selected for Comparison' in rv.data.decode()

        rv = self.test_client.get(f'/analysis/{self.test_fw_c.uid}')
        assert self.test_fw_c.uid in rv.data.decode()
        assert self.test_fw_c.name in rv.data.decode()
        rv = self.test_client.get(f'/comparison/add/{self.test_fw_c.uid}', follow_redirects=True)
        assert 'Remove All' in rv.data.decode()

    def _start_compare(self):
        rv = self.test_client.get('/compare', follow_redirects=True)
        assert b'Your compare task is in progress.' in rv.data, 'compare wait page not displayed correctly'

    def _show_comparison_results(self):
        rv = self.test_client.get(f'/compare/{self.test_fw_a.uid};{self.test_fw_c.uid}')
        assert self.test_fw_a.name.encode() in rv.data, 'test firmware a comparison not displayed correctly'
        assert self.test_fw_c.name.encode() in rv.data, 'test firmware b comparison not displayed correctly'
        assert b'File Coverage' in rv.data, 'comparison page not displayed correctly'

    def _show_home_page(self):
        rv = self.test_client.get('/')
        assert b'Latest Comparisons' in rv.data, 'latest comparisons not displayed on "home"'

    def _show_compare_browse(self):
        rv = self.test_client.get('/database/browse_compare')
        assert self.test_fw_a.name.encode() in rv.data, 'no compare result shown in browse'

    def _show_analysis_without_compare_list(self):
        rv = self.test_client.get(f'/analysis/{self.test_fw_a.uid}')
        assert b'Show list of known comparisons' not in rv.data

    def _show_analysis_with_compare_list(self):
        rv = self.test_client.get(f'/analysis/{self.test_fw_a.uid}')
        assert b'Show list of known comparisons' in rv.data

    def test_compare_firmwares(self):
        for firmware in [self.test_fw_a, self.test_fw_c]:
            self.upload_test_firmware(firmware)
        self.analysis_finished_event.wait(timeout=20)
        self._show_analysis_without_compare_list()
        self._add_firmwares_to_compare()
        self._start_compare()
        self.compare_finished_event.wait(timeout=20)
        self._show_comparison_results()
        self._show_home_page()
        self._show_compare_browse()
        self._show_analysis_with_compare_list()

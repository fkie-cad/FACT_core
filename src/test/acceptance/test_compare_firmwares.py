from test.acceptance.base_full_start import TestAcceptanceBaseFullStart


class TestAcceptanceCompareFirmwares(TestAcceptanceBaseFullStart):

    NUMBER_OF_FILES_TO_ANALYZE = 8
    NUMBER_OF_PLUGINS = 2

    def _add_firmwares_to_compare(self):
        rv = self.test_client.get(f'/analysis/{self.test_fw_a.uid}')
        self.assertIn(self.test_fw_a.uid, rv.data.decode(), '')
        rv = self.test_client.get(f'/comparison/add/{self.test_fw_a.uid}', follow_redirects=True)
        self.assertIn('Firmware Selected for Comparison', rv.data.decode())

        rv = self.test_client.get(f'/analysis/{self.test_fw_c.uid}')
        self.assertIn(self.test_fw_c.uid, rv.data.decode())
        self.assertIn(self.test_fw_c.name, rv.data.decode())
        rv = self.test_client.get(f'/comparison/add/{self.test_fw_c.uid}', follow_redirects=True)
        self.assertIn('Remove All', rv.data.decode())

    def _start_compare(self):
        rv = self.test_client.get('/compare', follow_redirects=True)
        self.assertIn(b'Your compare task is in progress.', rv.data, 'compare wait page not displayed correctly')

    def _show_comparison_results(self):
        rv = self.test_client.get(f'/compare/{self.test_fw_a.uid};{self.test_fw_c.uid}')
        self.assertIn(self.test_fw_a.name.encode(), rv.data, 'test firmware a comparison not displayed correctly')
        self.assertIn(self.test_fw_c.name.encode(), rv.data, 'test firmware b comparison not displayed correctly')
        self.assertIn(b'File Coverage', rv.data, 'comparison page not displayed correctly')

    def _show_home_page(self):
        rv = self.test_client.get('/')
        self.assertIn(b'Latest Comparisons', rv.data, 'latest comparisons not displayed on "home"')

    def _show_compare_browse(self):
        rv = self.test_client.get('/database/browse_compare')
        self.assertIn(self.test_fw_a.name.encode(), rv.data, 'no compare result shown in browse')

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

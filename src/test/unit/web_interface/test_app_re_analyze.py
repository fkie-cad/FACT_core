from helperFunctions.dataConversion import make_bytes
from helperFunctions.web_interface import overwrite_default_plugins
from test.common_helper import TEST_FW
from test.unit.web_interface.base import WebInterfaceTest


class TestAppReAnalyze(WebInterfaceTest):

    def test_app_re_analyze_get_invalid_firmware(self):
        rv = self.test_client.get('/update-analysis/invalid')
        assert b'File not found in database: invalid' in rv.data

    def test_app_re_analyze_get_valid_firmware(self):
        rv = self.test_client.get('/update-analysis/{}'.format(TEST_FW.uid))
        assert b'<h3 class="mb-3">update analysis of TEST_FW_HID</h3>' in rv.data
        assert b'value="default_plugin" unchecked' in rv.data
        assert b'mandatory_plugin' not in rv.data
        assert b'value="optional_plugin" checked' in rv.data

    def test_app_re_analyze_post_valid(self):
        form_data = {
            'device_name': '',
            'device_name_dropdown': TEST_FW.device_name,
            'device_part': '',
            'device_part_dropdown': TEST_FW.part,
            'device_class': TEST_FW.device_class,
            'version': TEST_FW.version,
            'vendor': TEST_FW.vendor,
            'release_date': TEST_FW.release_date,
            'tags': '',
            'analysis_systems': ["new_system"]}
        rv = self.test_client.post('/update-analysis/{}'.format(TEST_FW.uid), data=form_data)
        assert b'Upload Successful' in rv.data
        assert make_bytes(TEST_FW.uid) in rv.data
        self.assertEqual(self.mocked_interface.tasks[0].uid, TEST_FW.uid, "fw not added to intercom")
        self.assertIn("new_system", self.mocked_interface.tasks[0].scheduled_analysis, "new analysis system not scheduled")

    def test_overwrite_default_plugins(self):
        plugins_that_should_be_checked = ["optional_plugin"]
        result = overwrite_default_plugins(self.mocked_interface, plugins_that_should_be_checked)
        self.assertEqual(len(result.keys()), 4, "number of plug-ins changed")
        self.assertFalse(result['default_plugin'][2], "default plugin still checked")
        self.assertTrue(result['optional_plugin'][2], "optional plugin not checked")

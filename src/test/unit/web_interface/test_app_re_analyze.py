import re

from helperFunctions.data_conversion import make_bytes
from test.common_helper import TEST_FW


class TestAppReAnalyze:
    def test_app_re_analyze_get_invalid_firmware(self, test_client):
        rv = test_client.get('/update-analysis/invalid')
        assert b'File not found in database: invalid' in rv.data

    def test_app_re_analyze_get_valid_firmware(self, test_client):
        rv = test_client.get(f'/update-analysis/{TEST_FW.uid}')
        assert b'<h3 class="mb-1">update analysis of</h3>' in rv.data
        assert b'<h5 class="mb-3">TEST_FW_HID</h5>' in rv.data
        assert (
            re.search(rb'value="default_plugin"\s+checked>', rv.data) is None
        ), 'plugins that did not run for TEST_FW should not be checked'
        assert b'value="mandatory_plugin"' not in rv.data, 'mandatory plugins should not be listed'
        assert re.search(
            rb'value="optional_plugin"\s+checked>', rv.data
        ), 'optional plugins that did run for TEST_FW should be checked'

    def test_app_re_analyze_post_valid(self, test_client, intercom_task_list):
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
            'analysis_systems': ['new_system'],
        }
        rv = test_client.post(f'/update-analysis/{TEST_FW.uid}', data=form_data)
        assert b'Upload Successful' in rv.data
        assert make_bytes(TEST_FW.uid) in rv.data
        assert intercom_task_list[0].uid == TEST_FW.uid, 'fw not added to intercom'
        assert 'new_system' in intercom_task_list[0].scheduled_analysis, 'new analysis system not scheduled'

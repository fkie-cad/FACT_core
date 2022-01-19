# pylint: disable=protected-access,wrong-import-order,attribute-defined-outside-init
from flask import render_template_string

from test.unit.web_interface.base import WebInterfaceTest
from web_interface.components.jinja_filter import FilterClass


class TestAppShowAnalysis(WebInterfaceTest):

    def setup(self):
        self.filter = FilterClass(self.frontend.app, '', self.config, frontend_db=self.db_mock())

    def _get_template_filter_output(self, data, filter_name):
        with self.frontend.app.test_request_context():
            return render_template_string(
                f'<html><body><div>{{{{ {data} | {filter_name} | safe }}}}</div></body></html>'
            )

    def test_filter_replace_uid_with_file_name(self):
        test_string = '"abcdefghijk>deadbeef00000000000000000000000000000000000000000000000000000000_123<abcdefghijk"'
        result = self.filter._filter_replace_uid_with_file_name(test_string)
        assert '>test_name<' in result

        result = self._get_template_filter_output(test_string, 'replace_uid_with_file_name')
        assert '>test_name<' in result

    def test_filter_firmware_detail_tabular_field(self):
        test_firmware_meta_data = ('UID', 'HID', {'tag1': 'danger', 'tag2': 'default'}, 0)
        result = self._get_template_filter_output(test_firmware_meta_data, 'firmware_detail_tabular_field')
        for expected_part in ['/analysis/UID', 'HID', '>tag1<', '>tag2<']:
            assert expected_part in result

    def test_filter_replace_uid_with_hid(self):
        one_uid = '{}_1234'.format('a' * 64)
        assert self.filter._filter_replace_uid_with_hid('{0}_{0}'.format(one_uid)) == 'TEST_FW_HID_TEST_FW_HID'

    def test_filter_replace_comparison_uid_with_hid(self):
        one_uid = '{}_1234'.format('a' * 64)
        assert self.filter._filter_replace_comparison_uid_with_hid('{0};{0}'.format(one_uid)) == 'TEST_FW_HID  ||  TEST_FW_HID'

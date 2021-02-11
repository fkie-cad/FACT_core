# pylint: disable=protected-access,wrong-import-order

import pytest
from flask import render_template_string

from test.unit.web_interface.base import WebInterfaceTest
from web_interface.components.jinja_filter import FilterClass


class TestAppShowAnalysis(WebInterfaceTest):

    def setUp(self):  # pylint: disable=arguments-differ
        super().setUp()
        self.filter = FilterClass(self.frontend.app, '', self.config)

    def _get_template_filter_output(self, data, filter_name):
        with self.frontend.app.test_request_context():
            return render_template_string(
                '<html><body><div>{{{{ {data} | {filter_name} | safe }}}}</div></body></html>'.format(data=data, filter_name=filter_name)
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


def test_split_user_and_password_type_entry():  # pylint: disable=invalid-name
    new_test_entry_form = {'test:mosquitto': {'password': '123456'}}
    old_test_entry_form = {'test': {'password': '123456'}}
    expected_new_entry = {'test': {'mosquitto': {'password': '123456'}}}
    expected_old_entry = {'test': {'unix': {'password': '123456'}}}
    assert expected_new_entry == FilterClass._split_user_and_password_type_entry(new_test_entry_form)
    assert expected_old_entry == FilterClass._split_user_and_password_type_entry(old_test_entry_form)


@pytest.mark.parametrize('hid, uid, expected_output', [
    ('foo', 'bar', 'badge-secondary">foo'),
    ('foo', 'a152ccc610b53d572682583e778e43dc1f24ddb6577255bff61406bc4fb322c3_21078024', 'badge-primary">    <a'),
    ('suuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuper/long/human_readable_id', 'bar', '~uuuuuuuuuuuuuuuuuuuuuuuuuuuuper/long/human_readable_id'),
])
def test_virtual_path_element_to_span(hid, uid, expected_output):
    assert expected_output in FilterClass._virtual_path_element_to_span(hid, uid, 'root_uid')


class FilterClassMock:
    @staticmethod
    def _get_chart_element_count():
        return 10


@pytest.mark.parametrize('input_data, limit, expected_result', [
    (
        [('NX enabled', 1696), ('NX disabled', 207), ('Canary enabled', 9)],
        None,
        {
            'labels': ['NX enabled', 'NX disabled', 'Canary enabled'],
            'datasets': [{'data': [1696, 207, 9], 'backgroundColor': ['#4062fa', '#149df1', '#18cde4'], 'borderColor': '#fff', 'borderWidth': 2}]
        }
    ),
    (
        [('NX enabled', 1696), ('NX disabled', 207), ('Canary enabled', 9)],
        2,
        {
            'labels': ['NX enabled', 'NX disabled', 'rest'],
            'datasets': [{'data': [1696, 207, 9], 'backgroundColor': ['#4062fa', '#a0faa1'], 'borderColor': '#fff', 'borderWidth': 2}]
        }
    ),
    ([()], None, None)
])
def test_data_to_chart_limited(input_data, limit, expected_result):
    result = FilterClass.data_to_chart_limited(FilterClassMock(), input_data, limit=limit)
    assert result == expected_result

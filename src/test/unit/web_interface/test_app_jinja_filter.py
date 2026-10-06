import pytest
from flask import render_template_string

from web_interface.components.jinja_filter import FilterClass


@pytest.fixture
def filter_class(web_frontend):
    return FilterClass(web_frontend.app, web_frontend.db)


class TestAppShowAnalysis:
    def test_filter_replace_uid_with_file_name(self, web_frontend, filter_class):
        test_string = '"abcdefghijk>deadbeef00000000000000000000000000000000000000000000000000000000_123<abcdefghijk"'
        result = filter_class._filter_replace_uid_with_file_name(test_string)
        assert '>test_name<' in result

        result = _get_template_filter_output(web_frontend, test_string, 'replace_uid_with_file_name')
        assert '>test_name<' in result

    def test_filter_replace_uid_with_hid(self, filter_class):
        one_uid = f'{"a" * 64}_1234'
        assert filter_class._filter_replace_uid_with_hid(f'{one_uid}_{one_uid}') == 'TEST_FW_HID_TEST_FW_HID'

    def test_filter_replace_comparison_uid_with_hid(self, filter_class):
        one_uid = f'{"a" * 64}_1234'
        assert (
            filter_class._filter_replace_comparison_uid_with_hid(f'{one_uid};{one_uid}')
            == 'TEST_FW_HID  ||  TEST_FW_HID'
        )


def _get_template_filter_output(web_frontend, data, filter_name):
    with web_frontend.app.test_request_context():
        return render_template_string(
            f'<html><body><div>{{{{ data | {filter_name} | safe }}}}</div></body></html>', data=data
        ).replace('\n', '')

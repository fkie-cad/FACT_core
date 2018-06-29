from test.common_helper import TEST_FW
from test.unit.web_interface.base import WebInterfaceTest
from web_interface.components.jinja_filter import FilterClass
from flask import render_template_string


class TestAppShowAnalysis(WebInterfaceTest):

    def setUp(self):
        super().setUp()
        self.filter = FilterClass(self.frontend.app, '', self.config)
        self.test_fw = TEST_FW

    def _get_template_filter_output(self, data, filter_name):
        with self.frontend.app.test_request_context():
            return render_template_string(
                '<html><body><div>{{{{ "{data}" | {filter_name} | safe }}}}</div></body></html>'.format(data=data, filter_name=filter_name)
            )

    def test_filter_replace_uid_with_file_name(self):
        test_string = 'abcdefghijk>deadbeef00000000000000000000000000000000000000000000000000000000_123<abcdefghijk'
        result = self.filter._filter_replace_uid_with_file_name(test_string)
        assert '>test_name<' in result

        result = self._get_template_filter_output(test_string, 'replace_uid_with_file_name')
        assert '>test_name<' in result

    def test_filter_get_object_binary(self):
        result = self.filter._filter_get_object_binary(self.test_fw.uid)
        assert result == self.test_fw.binary

        result = self._get_template_filter_output(self.test_fw.uid, 'get_object_binary')
        assert self.test_fw.binary.__str__() in result

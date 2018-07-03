from flask import render_template_string

from test.unit.web_interface.base import WebInterfaceTest
from web_interface.components.jinja_filter import FilterClass


class TestAppShowAnalysis(WebInterfaceTest):

    def setUp(self):
        super().setUp()
        self.filter = FilterClass(self.frontend.app, '', self.config)

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

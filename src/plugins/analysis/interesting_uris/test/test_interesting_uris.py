import pytest
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.interesting_uris import AnalysisPlugin
from test.common_helper import create_test_file_object


@pytest.mark.parametrize('input_list, blacklist, expected_output', [
    ([], ['abc', 'def'], []),
    (['abcd', 'bcde'], [], ['abcd', 'bcde']),
    (['abcd', 'bcde', 'cdef', 'efgh'], ['abc', 'def'], ['bcde', 'efgh']),
    (['abcdefgh'], ['abc', 'def'], []),
])
def test_blacklist_ip_and_uris(input_list, blacklist, expected_output):
    assert AnalysisPlugin.blacklist_ip_and_uris(blacklist, input_list) == expected_output

"""
@pytest.mark.parametrize('input_list, blacklist, expected_output', [
    ([], ['abc', 'def'], []),
    (['abcd', 'bcde'], [], ['abcd', 'bcde']),
    (['abcd', 'bcde', 'cdef', 'efgh'], ['abc', 'def'], ['bcde', 'efgh']),
    (['abcdefgh'], ['abc', 'def'], []),
])
def test_whitelist_ip_and_uris(input_list, whitelist, expected_output):
    assert AnalysisPlugin.blacklist_ip_and_uris(whitelist, input_list) == expected_output
"""


class TestAnalysisPluginInterestingUris(AnalysisPluginTest):
    PLUGIN_NAME = 'interesting_uris'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_process_object(self):
        fo = create_test_file_object()
        fo.processed_analysis['ip_and_uri_finder'] = {
            'summary': ['1.2.3.4', 'www.example.com', 'www.interesting.receive.org']}
        self.analysis_plugin.process_object(fo)
        assert self.PLUGIN_NAME in fo.processed_analysis
        assert fo.processed_analysis[self.PLUGIN_NAME]['summary'] == ['www.interesting.receive.org']

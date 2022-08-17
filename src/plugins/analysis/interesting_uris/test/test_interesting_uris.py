import pytest

from test.common_helper import create_test_file_object  # pylint: disable=wrong-import-order
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.interesting_uris import AnalysisPlugin


@pytest.mark.parametrize(
    'input_list, blacklist, expected_output',
    [
        ([], ['abc', 'def'], []),
        (['abcd', 'bcde'], [], ['abcd', 'bcde']),
        (['abcd', 'bcde', 'cdef', 'efgh'], ['abc', 'def'], ['bcde', 'efgh']),
        (['abcdefgh'], ['abc', 'def'], []),
    ]
)
def test_blacklist_ip_and_uris(input_list, blacklist, expected_output):
    assert AnalysisPlugin.blacklist_ip_and_uris(blacklist, input_list) == expected_output


@pytest.mark.parametrize(
    'input_list, whitelist, expected_output',
    [
        ([], ['abc', 'def'], []),
        (['abcd', 'bcde'], [], []),
        (['abcd', 'bcde', 'cdef', 'efgh'], ['abcd', 'cdef'], ['abcd', 'cdef']),
        (['abcf', 'bcfg', 'abci', 'bdhi'], ['abc', 'hi'], ['abcf', 'abci', 'bdhi']),
        (['abcdefgh'], ['abc', 'def'], ['abcdefgh']),
    ]
)
def test_white_ip_and_uris(input_list, whitelist, expected_output):
    assert sorted(AnalysisPlugin.whitelist_ip_and_uris(whitelist, input_list)) == expected_output


class TestAnalysisPluginInterestingUris(AnalysisPluginTest):

    PLUGIN_NAME = 'interesting_uris'
    PLUGIN_CLASS = AnalysisPlugin

    def test_process_object(self):
        fo = create_test_file_object()
        fo.processed_analysis['ip_and_uri_finder'] = {
            'summary': ['1.2.3.4', 'www.example.com', 'www.interesting.receive.org']
        }
        self.analysis_plugin.process_object(fo)
        assert self.PLUGIN_NAME in fo.processed_analysis
        assert fo.processed_analysis[self.PLUGIN_NAME]['summary'] == ['www.interesting.receive.org']

    def test_remove_ip_v4_v6_addresses(self):
        assert self.analysis_plugin.remove_ip_v4_v6_addresses(['2001:db8::1', '127.0.255.250']) == []
        assert self.analysis_plugin.remove_ip_v4_v6_addresses(['abcd', '127.0.255.250', 'bcde']) == ['abcd', 'bcde']
        assert self.analysis_plugin.remove_ip_v4_v6_addresses(['abcd', '2001:db8::1', 'efgh']) == ['abcd', 'efgh']

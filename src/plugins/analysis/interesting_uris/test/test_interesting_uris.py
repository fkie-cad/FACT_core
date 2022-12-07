import pytest

from test.common_helper import create_test_file_object  # pylint: disable=wrong-import-order

from ..code.interesting_uris import AnalysisPlugin


@pytest.mark.parametrize(
    'input_list, blacklist, expected_output',
    [
        ([], ['abc', 'def'], []),
        (['abcd', 'bcde'], [], ['abcd', 'bcde']),
        (['abcd', 'bcde', 'cdef', 'efgh'], ['abc', 'def'], ['bcde', 'efgh']),
        (['abcdefgh'], ['abc', 'def'], []),
    ],
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
    ],
)
def test_white_ip_and_uris(input_list, whitelist, expected_output):
    assert sorted(AnalysisPlugin.whitelist_ip_and_uris(whitelist, input_list)) == expected_output


@pytest.mark.AnalysisPluginClass.with_args(AnalysisPlugin)
class TestAnalysisPluginInterestingUris:
    def test_process_object(self, analysis_plugin):
        fo = create_test_file_object()
        fo.processed_analysis['ip_and_uri_finder'] = {
            'summary': ['1.2.3.4', 'www.example.com', 'www.interesting.receive.org']
        }
        analysis_plugin.process_object(fo)
        assert analysis_plugin.NAME in fo.processed_analysis
        assert fo.processed_analysis[analysis_plugin.NAME]['summary'] == ['www.interesting.receive.org']

    def test_remove_ip_v4_v6_addresses(self, analysis_plugin):
        assert analysis_plugin.remove_ip_v4_v6_addresses(['2001:db8::1', '127.0.255.250']) == []
        assert analysis_plugin.remove_ip_v4_v6_addresses(['abcd', '127.0.255.250', 'bcde']) == ['abcd', 'bcde']
        assert analysis_plugin.remove_ip_v4_v6_addresses(['abcd', '2001:db8::1', 'efgh']) == ['abcd', 'efgh']

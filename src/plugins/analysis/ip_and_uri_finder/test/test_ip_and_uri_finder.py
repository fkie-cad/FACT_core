from __future__ import annotations


import tempfile
from collections import namedtuple

import pytest
from geoip2.errors import AddressNotFoundError

from objects.file import FileObject

from ..code.ip_and_uri_finder import AnalysisPlugin

MockResponse = namedtuple('MockResponse', ['location'])
MockLocation = namedtuple('MockLocation', ['latitude', 'longitude'])


class MockReader:
    def __init__(self):
        pass

    def city(self, address):  # noqa: C901, PLR0911
        if address == '128.101.101.101':
            return MockResponse(location=MockLocation(latitude=44.9759, longitude=-93.2166))
        if address == '1.2.3.4':
            return MockResponse(location=MockLocation(latitude=47.913, longitude=-122.3042))
        if address == '1.1.1.123':
            return MockResponse(location=MockLocation(latitude=-37.7, longitude=145.1833))
        if address == '255.255.255.255':
            return MockResponse(location=MockLocation(latitude=0.0, longitude=0.0))
        if address == '192.0.2.16':
            return MockResponse(location=MockLocation(latitude=1.1, longitude=1.1))
        if address == '1234:1234:abcd:abcd:1234:1234:abcd:abcd':
            return MockResponse(location=MockLocation(latitude=2.1, longitude=2.1))
        if address == '2001:db8:0:0:8d3::':
            return MockResponse(location=MockLocation(latitude=3.1, longitude=3.1))
        if address == '127.101.101.101':
            return MockResponse(location=MockLocation(latitude=4.1, longitude=4.1))
        if address == '1.1.2.345':
            raise AddressNotFoundError('')
        if address == 'aaa':
            raise ValueError()
        return None


@pytest.fixture
def ip_and_uri_finder_plugin(analysis_plugin):
    analysis_plugin.reader = MockReader()
    return analysis_plugin


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginIpAndUriFinder:
    def test_process_object_ips(self, ip_and_uri_finder_plugin):
        with tempfile.NamedTemporaryFile() as tmp:
            with open(tmp.name, 'w') as fp:  # noqa: PTH123
                fp.write(
                    '1.2.3.4 abc 1.1.1.1234 abc 3. 3. 3. 3 abc 1255.255.255.255 1234:1234:abcd:abcd:1234:1234:abcd:abc'
                    'd xyz 2001:db8::8d3:: xyz 2001:db8:0:0:8d3::'
                )
            tmp_fo = FileObject(file_path=tmp.name)
            processed_object = ip_and_uri_finder_plugin.process_object(tmp_fo)
            results = processed_object.processed_analysis[ip_and_uri_finder_plugin.NAME]
        assert results['uris'] == []
        assert {
            ('1.2.3.4', '47.913, -122.3042'),
            ('1.1.1.123', '-37.7, 145.1833'),
        } == set(results['ips_v4'])
        assert len(
            [
                ('1.2.3.4', '47.913, -122.3042'),
                ('1.1.1.123', '-37.7, 145.1833'),
            ]
        ) == len(results['ips_v4'])
        assert {
            ('1234:1234:abcd:abcd:1234:1234:abcd:abcd', '2.1, 2.1'),
            ('2001:db8:0:0:8d3::', '3.1, 3.1'),
        } == set(results['ips_v6'])
        assert len(
            [
                ('1234:1234:abcd:abcd:1234:1234:abcd:abcd', '2.1, 2.1'),
                ('2001:db8:0:0:8d3::', '3.1, 3.1'),
            ]
        ) == len(results['ips_v6'])

    def test_process_object_uris(self, ip_and_uri_finder_plugin):
        with tempfile.NamedTemporaryFile() as tmp:
            with open(tmp.name, 'w') as fp:  # noqa: PTH123
                fp.write(
                    'http://www.google.de https://www.test.de/test/?x=y&1=2 ftp://ftp.is.co.za/rfc/rfc1808.txt '
                    'telnet://192.0.2.16:80/'
                )
            tmp_fo = FileObject(file_path=tmp.name)
            processed_object = ip_and_uri_finder_plugin.process_object(tmp_fo)
            results = processed_object.processed_analysis[ip_and_uri_finder_plugin.NAME]
        assert {
            'http://www.google.de',
            'https://www.test.de/test/',
            'ftp://ftp.is.co.za/rfc/rfc1808.txt',
            'telnet://192.0.2.16:80/',
        } == set(results['uris'])
        assert len(
            [
                'http://www.google.de',
                'https://www.test.de/test/',
                'ftp://ftp.is.co.za/rfc/rfc1808.txt',
                'telnet://192.0.2.16:80/',
            ]
        ) == len(results['uris'])

    def test_add_geo_uri_to_ip(self, ip_and_uri_finder_plugin):
        test_data = {
            'ips_v4': ['128.101.101.101', '255.255.255.255'],
            'ips_v6': ['1234:1234:abcd:abcd:1234:1234:abcd:abcd'],
            'uris': 'http://www.google.de',
        }
        results = ip_and_uri_finder_plugin.add_geo_uri_to_ip(test_data)
        assert results['uris'] == 'http://www.google.de'
        assert [('128.101.101.101', '44.9759, -93.2166'), ('255.255.255.255', '0.0, 0.0')] == results['ips_v4']
        assert [('1234:1234:abcd:abcd:1234:1234:abcd:abcd', '2.1, 2.1')] == results['ips_v6']

    def test_find_geo_location(self, ip_and_uri_finder_plugin):
        assert ip_and_uri_finder_plugin.find_geo_location('128.101.101.101') == '44.9759, -93.2166'
        assert ip_and_uri_finder_plugin.find_geo_location('127.101.101.101') == '4.1, 4.1'

        with pytest.raises(AddressNotFoundError):
            ip_and_uri_finder_plugin.find_geo_location('1.1.2.345')
        with pytest.raises(ValueError):  # noqa: PT011
            ip_and_uri_finder_plugin.find_geo_location('aaa')

    def test_link_ips_with_geo_location(self, ip_and_uri_finder_plugin):
        ip_addresses = ['128.101.101.101', '255.255.255.255']
        expected_results = [('128.101.101.101', '44.9759, -93.2166'), ('255.255.255.255', '0.0, 0.0')]
        assert ip_and_uri_finder_plugin.link_ips_with_geo_location(ip_addresses) == expected_results

    def test_get_summary(self):
        results = {
            'uris': ['http://www.google.de'],
            'ips_v4': [('128.101.101.101', '44.9759, -93.2166')],
            'ips_v6': [('1234:1234:abcd:abcd:1234:1234:abcd:abcd', '2.1, 2.1')],
        }
        expected_results = ['http://www.google.de', '128.101.101.101', '1234:1234:abcd:abcd:1234:1234:abcd:abcd']
        assert AnalysisPlugin._get_summary(results), expected_results

    def test_remove_blacklisted(self, ip_and_uri_finder_plugin):
        input_list = ['1.1.1.1', 'blah', '0.0.0.0']
        blacklist = [r'[0-9].{4}', r'x.y']
        assert ip_and_uri_finder_plugin._remove_blacklisted(input_list, blacklist) == ['blah']

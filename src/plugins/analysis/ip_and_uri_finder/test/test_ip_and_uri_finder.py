from __future__ import annotations

import tempfile
from collections import namedtuple
from pathlib import Path

import pytest
from geoip2.errors import AddressNotFoundError

from ..code.ip_and_uri_finder import AnalysisPlugin, _remove_blacklisted

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
        with tempfile.NamedTemporaryFile() as tmp, Path(tmp.name).open('w') as fp:
            fp.write(
                '1.2.3.4 abc 1.1.1.1234 abc 3. 3. 3. 3 abc 1255.255.255.255 1234:1234:abcd:abcd:1234:1234:abcd:abc'
                'd xyz 2001:db8::8d3:: xyz 2001:db8:0:0:8d3::'
            )
            fp.seek(0)
            results = ip_and_uri_finder_plugin.analyze(fp, {}, {})
        assert results.uris == []
        assert len(results.ips_v4) == 2
        ip_v4_addresses = {ipa.address: f'{ipa.location.latitude}, {ipa.location.longitude}' for ipa in results.ips_v4}
        assert ip_v4_addresses == {
            '1.2.3.4': '47.913, -122.3042',
            '1.1.1.123': '-37.7, 145.1833',
        }
        assert len(results.ips_v6) == 2
        ip_v6_addresses = {ipa.address: f'{ipa.location.latitude}, {ipa.location.longitude}' for ipa in results.ips_v6}
        assert ip_v6_addresses == {
            '1234:1234:abcd:abcd:1234:1234:abcd:abcd': '2.1, 2.1',
            '2001:db8:0:0:8d3::': '3.1, 3.1',
        }

        assert set(ip_and_uri_finder_plugin.summarize(results)) == {*ip_v4_addresses, *ip_v6_addresses}

    def test_process_object_uris(self, ip_and_uri_finder_plugin):
        with tempfile.NamedTemporaryFile() as tmp, Path(tmp.name).open('w') as fp:
            fp.write(
                'http://www.google.de https://www.test.de/test/?x=y&1=2 ftp://ftp.is.co.za/rfc/rfc1808.txt '
                'telnet://192.0.2.16:80/'
            )
            fp.seek(0)
            results = ip_and_uri_finder_plugin.analyze(fp, {}, {})
        assert set(results.uris) == {
            'http://www.google.de',
            'https://www.test.de/test/',
            'ftp://ftp.is.co.za/rfc/rfc1808.txt',
            'telnet://192.0.2.16:80/',
        }
        assert len(results.uris) == 4

        assert set(ip_and_uri_finder_plugin.summarize(results)) == set(results.uris).union({'192.0.2.16'})

    def test_find_geo_location(self, ip_and_uri_finder_plugin):
        location = ip_and_uri_finder_plugin.find_geo_location('128.101.101.101')
        assert location.latitude == 44.9759
        assert location.longitude == -93.2166
        location = ip_and_uri_finder_plugin.find_geo_location('127.101.101.101')
        assert location.latitude == 4.1
        assert location.longitude == 4.1

        assert ip_and_uri_finder_plugin.find_geo_location('1.1.2.345') is None
        assert ip_and_uri_finder_plugin.find_geo_location('aaa') is None

    def test_remove_blacklisted(self, ip_and_uri_finder_plugin):
        input_list = ['1.1.1.1', 'blah', '0.0.0.0']
        blacklist = [r'[0-9].{4}', r'x.y']
        assert _remove_blacklisted(input_list, blacklist) == ['blah']

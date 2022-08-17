# pylint: disable=protected-access
import tempfile
from collections import namedtuple
from unittest.mock import patch

from geoip2.errors import AddressNotFoundError

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest  # pylint: disable=wrong-import-order

from ..code.ip_and_uri_finder import AnalysisPlugin

MockResponse = namedtuple('MockResponse', ['location'])
MockLocation = namedtuple('MockLocation', ['latitude', 'longitude'])


class MockReader:
    def __init__(self, database_path):
        pass

    def city(self, address):  # pylint: disable=too-complex,inconsistent-return-statements,no-self-use,too-many-return-statements
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
            raise AddressNotFoundError()
        if address == 'aaa':
            raise ValueError()


class TestAnalysisPluginIpAndUriFinder(AnalysisPluginTest):

    PLUGIN_NAME = 'ip_and_uri_finder'
    PLUGIN_CLASS = AnalysisPlugin

    @patch('geoip2.database.Reader', MockReader)
    def setUp(self):
        super().setUp()

    @patch('geoip2.database.Reader', MockReader)
    def test_process_object_ips(self):
        with tempfile.NamedTemporaryFile() as tmp:
            with open(tmp.name, 'w') as fp:
                fp.write('1.2.3.4 abc 1.1.1.1234 abc 3. 3. 3. 3 abc 1255.255.255.255 1234:1234:abcd:abcd:1234:1234:abcd:abc'
                         'd xyz 2001:db8::8d3:: xyz 2001:db8:0:0:8d3::')
            tmp_fo = FileObject(file_path=tmp.name)
            processed_object = self.analysis_plugin.process_object(tmp_fo)
            results = processed_object.processed_analysis[self.PLUGIN_NAME]
        self.assertEqual(results['uris'], [])
        self.assertCountEqual([('1.2.3.4', '47.913, -122.3042'), ('1.1.1.123', '-37.7, 145.1833')], results['ips_v4'])
        self.assertCountEqual([('1234:1234:abcd:abcd:1234:1234:abcd:abcd', '2.1, 2.1'), ('2001:db8:0:0:8d3::', '3.1, 3.1')],
                              results['ips_v6'])

    @patch('geoip2.database.Reader', MockReader)
    def test_process_object_uris(self):
        with tempfile.NamedTemporaryFile() as tmp:
            with open(tmp.name, 'w') as fp:
                fp.write('http://www.google.de https://www.test.de/test/?x=y&1=2 ftp://ftp.is.co.za/rfc/rfc1808.txt '
                         'telnet://192.0.2.16:80/')
            tmp_fo = FileObject(file_path=tmp.name)
            processed_object = self.analysis_plugin.process_object(tmp_fo)
            results = processed_object.processed_analysis[self.PLUGIN_NAME]
        self.assertCountEqual(['http://www.google.de', 'https://www.test.de/test/',
                               'ftp://ftp.is.co.za/rfc/rfc1808.txt',
                               'telnet://192.0.2.16:80/'], results['uris'])

    @patch('geoip2.database.Reader', MockReader)
    def test_add_geo_uri_to_ip(self):
        test_data = {'ips_v4': ['128.101.101.101', '255.255.255.255'],
                     'ips_v6': ['1234:1234:abcd:abcd:1234:1234:abcd:abcd'],
                     'uris': 'http://www.google.de'}
        results = self.analysis_plugin.add_geo_uri_to_ip(test_data)
        self.assertEqual('http://www.google.de', results['uris'])
        self.assertEqual([('128.101.101.101', '44.9759, -93.2166'),
                          ('255.255.255.255', '0.0, 0.0')], results['ips_v4'])
        self.assertEqual([('1234:1234:abcd:abcd:1234:1234:abcd:abcd', '2.1, 2.1')], results['ips_v6'])

    @patch('geoip2.database.Reader', MockReader(None))
    def test_find_geo_location(self):
        self.assertEqual(self.analysis_plugin.find_geo_location('128.101.101.101'), '44.9759, -93.2166')
        self.assertEqual(self.analysis_plugin.find_geo_location('127.101.101.101'), '4.1, 4.1')

        with self.assertRaises(AddressNotFoundError):
            self.analysis_plugin.find_geo_location('1.1.2.345')
        with self.assertRaises(ValueError):
            self.analysis_plugin.find_geo_location('aaa')

    @patch('geoip2.database.Reader', MockReader)
    def test_link_ips_with_geo_location(self):
        ip_addresses = ['128.101.101.101', '255.255.255.255']
        expected_results = [('128.101.101.101', '44.9759, -93.2166'),
                            ('255.255.255.255', '0.0, 0.0')]
        self.assertEqual(self.analysis_plugin.link_ips_with_geo_location(ip_addresses), expected_results)

    def test_get_summary(self):
        results = {
            'uris': ['http://www.google.de'],
            'ips_v4': [('128.101.101.101', '44.9759, -93.2166')],
            'ips_v6': [('1234:1234:abcd:abcd:1234:1234:abcd:abcd', '2.1, 2.1')],
        }
        expected_results = ['http://www.google.de', '128.101.101.101', '1234:1234:abcd:abcd:1234:1234:abcd:abcd']
        self.assertEqual(AnalysisPlugin._get_summary(results), expected_results)

    def test_remove_blacklisted(self):
        input_list = ['1.1.1.1', 'blah', '0.0.0.0']
        blacklist = [r'[0-9].{4}', r'x.y']
        self.assertEqual(self.analysis_plugin._remove_blacklisted(input_list, blacklist), ['blah'])

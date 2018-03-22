import tempfile
from collections import namedtuple
from unittest.mock import patch

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.ip_and_uri_finder import AnalysisPlugin

MockResponse = namedtuple('MockResponse', ['location'])
MockLocation = namedtuple('MockLocation', ['latitude', 'longitude'])


class MockReader:
    def __init__(self, database_path):
        pass

    def city(self, address):
        if address == '128.101.101.101':
            return MockResponse(location=MockLocation(latitude=44.9759, longitude=-93.2166))
        if address == '1.2.3.4':
            return MockResponse(location=MockLocation(latitude=47.913, longitude=-122.3042))
        if address == '1.1.1.123':
            return MockResponse(location=MockLocation(latitude=-37.7, longitude=145.1833))


class TestAnalysisPluginIpAndUriFinder(AnalysisPluginTest):

    PLUGIN_NAME = "ip_and_uri_finder"

    @patch('geoip2.database.Reader', MockReader)
    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    @patch('geoip2.database.Reader', MockReader)
    def test_process_object_ips(self):
        tmp = tempfile.NamedTemporaryFile()
        with open(tmp.name, "w") as fp:
            fp.write("1.2.3.4 abc 1.1.1.1234 abc 3. 3. 3. 3 abc 1255.255.255.255 1234:1234:abcd:abcd:1234:1234:abcd:abc"
                     "d xyz 2001:db8::8d3:: xyz 2001:db8:0:0:8d3::")
        tmp_fo = FileObject(file_path=tmp.name)
        processed_object = self.analysis_plugin.process_object(tmp_fo)
        results = processed_object.processed_analysis[self.PLUGIN_NAME]
        tmp.close()
        self.assertEqual(results["uris"], [])
        self.assertIn({"ip": "1.2.3.4", "geo_location": "(47.913, -122.3042)"}, results["ips_v4"])
        self.assertIn({"ip": "1.1.1.123", "geo_location": "(-37.7, 145.1833)"}, results["ips_v4"])
        self.assertIn({"ip": "255.255.255.255", "geo_location": ""}, results["ips_v4"])
        self.assertIn({"ip": "1234:1234:abcd:abcd:1234:1234:abcd:abcd", "geo_location": ""}, results["ips_v6"])
        self.assertIn({"ip": "2001:db8:0:0:8d3::", "geo_location": ""}, results["ips_v6"])

    @patch('geoip2.database.Reader', MockReader)
    def test_process_object_uris(self):
        tmp = tempfile.NamedTemporaryFile()
        with open(tmp.name, "w") as fp:
            fp.write("http://www.google.de https://www.test.de/test/?x=y&1=2 ftp://ftp.is.co.za/rfc/rfc1808.txt "
                     "telnet://192.0.2.16:80/")
        tmp_fo = FileObject(file_path=tmp.name)
        processed_object = self.analysis_plugin.process_object(tmp_fo)
        results = processed_object.processed_analysis[self.PLUGIN_NAME]
        tmp.close()
        self.assertIn("http://www.google.de", results["uris"])
        self.assertIn("https://www.test.de/test/", results["uris"])
        self.assertIn("ftp://ftp.is.co.za/rfc/rfc1808.txt", results["uris"])
        self.assertIn("telnet://192.0.2.16:80/", results["uris"])

    @patch('geoip2.database.Reader', MockReader)
    def test_add_geouri_to_ip(self):
        test_data = {'ips_v4': ['128.101.101.101', '255.255.255.255'],
                     'ips_v6': ["1234:1234:abcd:abcd:1234:1234:abcd:abcd"],
                     "uris": "http://www.google.de"}
        results = self.analysis_plugin.add_geo_uri_to_ip(test_data)
        self.assertEqual("http://www.google.de", results["uris"])
        self.assertEqual([{"ip": "128.101.101.101", "geo_location": "(44.9759, -93.2166)"},
                          {"ip": "255.255.255.255", "geo_location": ""}], results["ips_v4"])
        self.assertEqual([{"ip": "1234:1234:abcd:abcd:1234:1234:abcd:abcd", "geo_location": ""}], results["ips_v6"])

    @patch('geoip2.database.Reader', MockReader)
    def test_find_geo_location(self):
        self.assertEqual(self.analysis_plugin.find_geo_location('128.101.101.101'), (44.9759, -93.2166))
        self.assertEqual(self.analysis_plugin.find_geo_location('127.101.101.101'), "")
        self.assertEqual(self.analysis_plugin.find_geo_location('255.255.255.255'), "")

    @patch('geoip2.database.Reader', MockReader)
    def test_link_ips_with_geo_location(self):
        ip_adresses = ["128.101.101.101", "255.255.255.255"]
        expected_results = [{"ip": "128.101.101.101", "geo_location": "(44.9759, -93.2166)"},
                            {"ip": "255.255.255.255", "geo_location": ""}]
        self.assertEqual(self.analysis_plugin.link_ips_with_geo_location(ip_adresses), expected_results)

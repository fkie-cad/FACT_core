import tempfile

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.ip_and_uri_finder import AnalysisPlugin


class TestAnalysisPluginIpAndUriFinder(AnalysisPluginTest):

    PLUGIN_NAME = "ip_and_uri_finder"

    def setUp(self):
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_process_object_ips(self):
        tmp = tempfile.NamedTemporaryFile()
        with open(tmp.name, "w") as fp:
            fp.write("1.2.3.4 abc 1.1.1.1234 abc 3. 3. 3. 3 abc 1255.255.255.255 1234:1234:abcd:abcd:1234:1234:abcd:abc"
                     "d xyz 2001:db8::8d3:: xyz 2001:db8:0:0:8d3::")
        tmp_fo = FileObject(file_path=tmp.name)
        processed_object = self.analysis_plugin.process_object(tmp_fo)
        results = processed_object.processed_analysis[self.PLUGIN_NAME]
        tmp.close()
        expected_results_v4 = {"1.2.3.4", "1.1.1.123", "255.255.255.255"}
        expected_results_v6 = {"1234:1234:abcd:abcd:1234:1234:abcd:abcd", "2001:db8:0:0:8d3::"}
        self.assertEqual(results["uris"], [])
        self.assertEqual(expected_results_v4, set(results["ips_v4"]))
        self.assertEqual(expected_results_v6, set(results["ips_v6"]))

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

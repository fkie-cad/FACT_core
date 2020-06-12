from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.cwe_checker import AnalysisPlugin, BAP_TIMEOUT, DOCKER_IMAGE


class TestCweCheckerFunctions(AnalysisPluginTest):

    PLUGIN_NAME = 'cwe_checker'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        # TODO: Mock calls to BAP
        AnalysisPlugin._get_module_versions = lambda self: {}
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_parse_module_version(self):
        data = 'INFO: [cwe_checker] module_versions: {"CWE190": "0.1", "CWE215": "0.1", "CWE243": "0.1", "CWE248": "0.1", "CWE332": "0.1", "CWE367": "0.1", "CWE426": "0.1", "CWE457": "0.1", "CWE467": "0.1", "CWE476": "0.2", "CWE560": "0.1", "CWE676": "0.1", "CWE782": "0.1"}'
        expected_result = {'CWE190': '0.1',
                           'CWE215': '0.1',
                           'CWE243': '0.1',
                           'CWE248': '0.1',
                           'CWE332': '0.1',
                           'CWE367': '0.1',
                           'CWE426': '0.1',
                           'CWE457': '0.1',
                           'CWE467': '0.1',
                           'CWE476': '0.2',
                           'CWE560': '0.1',
                           'CWE676': '0.1',
                           'CWE782': '0.1'}
        res = self.analysis_plugin._parse_module_versions(data)
        self.assertEqual(res, expected_result)

    def test_build_bap_command(self):
        fo = FileObject(file_path='/foo')
        expected_result = 'timeout --signal=SIGKILL {}m docker run --rm -v {}:/tmp/input {} bap /tmp/input '\
                          '--pass=cwe-checker --cwe-checker-json --cwe-checker-no-logging'.format(
                              BAP_TIMEOUT, fo.file_path, DOCKER_IMAGE)
        assert self.analysis_plugin._build_bap_command(fo) == expected_result

    def test_parse_bap_output(self):
        test_data = """{
        "binary": "test/artificial_samples/build/cwe_190_x86_gcc.out",
        "time": 1564489060.0,
        "warnings": [
        {
        "name": "CWE190",
        "version": "0.1",
        "addresses": [ "0x6BC:32u" ],
        "symbols": [ "malloc" ],
        "other": [],
        "description":
        "(Integer Overflow or Wraparound) Potential overflow due to multiplication at 0x6BC:32u (malloc)"
        }]}"""
        result = self.analysis_plugin._parse_bap_output(test_data)
        print(result)
        assert isinstance(result, dict)
        assert len(result.keys()) == 1
        assert isinstance(result['CWE190'], dict)

    def test_is_supported_arch(self):
        fo = FileObject()
        test_data = 'ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=8e756708f62592be105b5e8b423080d38ddc8391, stripped'
        fo.processed_analysis = {'file_type': {'full': test_data}}
        assert self.analysis_plugin._is_supported_arch(fo)

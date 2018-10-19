import os

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.cwe_checker import AnalysisPlugin, CweWarningParser, BAP_TIMEOUT, PATH_TO_BAP


class TestCweCheckerFunctions(AnalysisPluginTest):

    PLUGIN_NAME = 'cwe_checker'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        # TODO: Mock calls to BAP
        AnalysisPlugin._get_module_versions = lambda self: {}
        self.analysis_plugin = AnalysisPlugin(self, config=config, docker=False)

    def test_cwe_warning_parser_can_parse_warning(self):
        data = '2018-02-16 13:27:35.552 WARN : [CWE476] {0.1} (NULL Pointer Dereference) There is no check if the return value is NULL at 0x104A0:32u/00000108 (malloc).'
        p = CweWarningParser()
        res = p.parse(data)
        self.assertEqual(res.name, '[CWE476] (NULL Pointer Dereference)')
        self.assertEqual(res.plugin_version, '0.1')
        self.assertEqual(res.warning.strip(), 'There is no check if the return value is NULL at 0x104A0/00000108 (malloc)')

    def test_cwe_warning_parser_does_not_parse_empty_warning(self):
        p = CweWarningParser()
        res = p.parse("")
        self.assertEqual(res, None)

    def test_parse_module_version(self):
        data = '018-02-16 13:33:37.571 INFO : [cwe_checker] module_versions: (("CWE215" "0.1") ("CWE243" "0.1") ("CWE332" "0.1") ("CWE367" "0.1") ("CWE415" "0.1") ("CWE426" "0.1") ("CWE467" "0.1") ("CWE476" "0.1") ("CWE676" "0.1"))'
        expected_result = {'CWE215': '0.1',
                           'CWE243': '0.1',
                           'CWE332': '0.1',
                           'CWE367': '0.1',
                           'CWE415': '0.1',
                           'CWE426': '0.1',
                           'CWE467': '0.1',
                           'CWE476': '0.1',
                           'CWE676': '0.1'}
        res = self.analysis_plugin._parse_module_versions(data)
        self.assertEqual(res, expected_result)

    def test_build_bap_command(self):
        self.analysis_plugin.docker = True
        fo = FileObject(file_path='/foo')
        assert self.analysis_plugin._build_bap_command(fo) == 'timeout --signal=SIGKILL {}m docker run -v {}:/tmp/input cwe-checker:latest bap /tmp/input --pass=cwe-checker --cwe-checker-config=/home/bap/cwe_checker/src/config.json'.format(BAP_TIMEOUT, fo.file_path)

    def test_build_bap_command_no_docker(self):
        self.analysis_plugin.docker = False
        fo = FileObject(file_path='/foo')
        assert self.analysis_plugin._build_bap_command(fo) == 'timeout --signal=SIGKILL {}m {} {} --pass=cwe-checker --cwe-checker-config={}/code/../internal/src/config.json'.format(
            BAP_TIMEOUT,
            PATH_TO_BAP,
            fo.file_path,
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

    def test_parse_bap_output(self):
        output = ''
        result = self.analysis_plugin._parse_bap_output(output)
        assert isinstance(result, dict)

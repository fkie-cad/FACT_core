import os

from common_helper_files import get_dir_of_file
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from ..code.cwe_checker import AnalysisPlugin, CweWarningParser


class MockFileObject(object):

    def __init__(self, file_path):
        self.file_path = file_path
        self.binary = open(file_path, 'rb').read()
        self.processed_analysis = {'file_type': {'full': 'ELFarm'}}


class TestCweCheckerFunctions(AnalysisPluginTest):

    PLUGIN_NAME = 'cwe_checker'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        # TODO: Mock calls to BAP
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_cwe_warning_parser_can_parse_warning(self):
        data = '2018-02-16 13:27:35.552 WARN : [CWE476] {0.1} (NULL Pointer Dereference) There is no check if the return value is NULL at 0x104A0:32u/00000108 (malloc).'
        p = CweWarningParser()
        res = p.parse(data)
        self.assertEqual(res.name, '[CWE476] (NULL Pointer Dereference)')
        self.assertEqual(res.plugin_version, '0.1')

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

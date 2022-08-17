# pylint: disable=protected-access
from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest  # pylint: disable=wrong-import-order

from ..code.cwe_checker import AnalysisPlugin


class TestCweCheckerFunctions(AnalysisPluginTest):

    PLUGIN_NAME = 'cwe_checker'
    PLUGIN_CLASS = AnalysisPlugin

    def test_parse_cwe_checker_output(self):
        test_data = """[
            {
                "name": "CWE676",
                "version": "0.1",
                "addresses": [
                    "00103042"
                ],
                "tids": [
                    "instr_00103042_2"
                ],
                "symbols": [
                    "FUN_00102ef0"
                ],
                "other": [
                    [
                        "dangerous_function",
                        "strlen"
                    ]
                ],
                "description": "(Use of Potentially Dangerous Function) FUN_00102ef0 (00103042) -> strlen",
            }
        ]"""
        result = self.analysis_plugin._parse_cwe_checker_output(test_data)
        print(result)
        assert isinstance(result, dict)
        assert len(result.keys()) == 1
        assert isinstance(result['CWE676'], dict)

    def test_is_supported_arch(self):
        fo = FileObject()
        test_data = (
            'ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, '
            'interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, '
            'BuildID[sha1]=8e756708f62592be105b5e8b423080d38ddc8391, stripped'
        )
        fo.processed_analysis = {'file_type': {'full': test_data}}
        assert self.analysis_plugin._is_supported_arch(fo)

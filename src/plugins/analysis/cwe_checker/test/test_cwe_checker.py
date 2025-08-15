import pytest

from plugins.analysis.cwe_checker.code.cwe_checker import AnalysisPlugin
from plugins.analysis.file_type.code.file_type import AnalysisPlugin as FileTypePlugin


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestCweCheckerFunctions:
    def test_parse_cwe_checker_output(self, analysis_plugin):
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
                "description": "(Use of Potentially Dangerous Function) FUN_00102ef0 (00103042) -> strlen"
            }
        ]"""
        result = analysis_plugin._parse_cwe_checker_output(test_data)
        assert isinstance(result, dict)
        assert len(result.keys()) == 1
        assert isinstance(result['CWE676'], dict)

    def test_is_supported_arch(self, analysis_plugin):
        test_data = (
            'ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, '
            'interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, '
            'BuildID[sha1]=8e756708f62592be105b5e8b423080d38ddc8391, stripped'
        )
        type_analysis = FileTypePlugin.Schema.model_validate({'full': test_data, 'mime': 'application/x-sharedlib'})
        assert analysis_plugin._is_supported_arch(type_analysis)

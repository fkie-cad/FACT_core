from pathlib import Path

import pytest

from plugins.analysis.cwe_checker.code.cwe_checker import AnalysisPlugin
from plugins.analysis.file_type.code.file_type import AnalysisPlugin as FileTypePlugin

TEST_FILE = Path(__file__).parent / 'data' / 'cwe_367'
FILE_TYPE_ANALYSIS = FileTypePlugin.Schema(
    full=(
        'ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, '
        'interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, '
        'BuildID[sha1]=8e756708f62592be105b5e8b423080d38ddc8391, stripped'
    ),
    mime='application/x-sharedlib',
)


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

    @pytest.mark.parametrize(
        ('full_type', 'expected'),
        [
            (FILE_TYPE_ANALYSIS.full, True),
            ('ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV)', True),
            ('ELF 32-bit LSB executable, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV)', True),
            ('ELF 64-bit LSB executable, LoongArch, version 1 (SYSV), dynamically linked', True),
            ('ELF 64-bit MSB executable, SPARC V9, relaxed memory ordering, version 1 (SYSV)', True),
            ('ELF 32-bit MSB executable, SPARC32PLUS, V8+ Required, total store ordering, version 1 (SYSV)', False),
            ('ELF 32-bit MSB executable, SPARC, version 1 (SYSV), dynamically linked', False),
        ],
    )
    def test_is_supported_arch(self, analysis_plugin, full_type, expected):
        file_type = FileTypePlugin.Schema(full=full_type, mime='application/x-executable')
        assert analysis_plugin._is_supported_arch(file_type) == expected

    def test_analyze_and_summarize(self, analysis_plugin: AnalysisPlugin):
        with TEST_FILE.open('rb') as fp:
            dependencies = {
                'file_type': FILE_TYPE_ANALYSIS,
            }
            results = analysis_plugin.analyze(fp, {}, dependencies)
        summary = analysis_plugin.summarize(results)

        assert sorted(summary) == ['CWE119', 'CWE252', 'CWE367', 'CWE676']

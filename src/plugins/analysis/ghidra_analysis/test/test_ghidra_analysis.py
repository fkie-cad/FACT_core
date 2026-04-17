"""Tests for the ghidra_analysis plugin.

Docker / Ghidra are not available in unit-test environments, so
``run_docker_container`` is mocked throughout.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from plugins.analysis.ghidra_analysis.code.ghidra_analysis import AnalysisPlugin, FunctionInfo

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SAMPLE_RESULT = {
    'functions': [
        {
            'name': 'main',
            'address': '0x00401000',
            'pseudocode': 'int main(void) { puts("hello"); return 0; }',
            'callees': ['puts'],
        },
        {
            'name': 'helper',
            'address': '0x00401050',
            'pseudocode': 'void helper(void) { }',
            'callees': [],
        },
    ]
}


def _make_docker_result(result_json: str | None, output_dir: str) -> CompletedProcess:
    """Write *result_json* into *output_dir*/result.json and return a fake CompletedProcess."""
    if result_json is not None:
        (Path(output_dir) / 'result.json').write_text(result_json, encoding='utf-8')
    return CompletedProcess(args=['entrypoint'], returncode=0, stdout='', stderr=None)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestGhidraAnalysisPlugin:
    # ------------------------------------------------------------------
    # _parse_ghidra_output
    # ------------------------------------------------------------------

    def test_parse_ghidra_output_basic(self, analysis_plugin: AnalysisPlugin):
        functions = analysis_plugin._parse_ghidra_output(json.dumps(SAMPLE_RESULT))
        assert len(functions) == 2
        names = {f.name for f in functions}
        assert names == {'main', 'helper'}

    def test_parse_ghidra_output_callees(self, analysis_plugin: AnalysisPlugin):
        functions = analysis_plugin._parse_ghidra_output(json.dumps(SAMPLE_RESULT))
        main_func = next(f for f in functions if f.name == 'main')
        assert main_func.callees == ['puts']

    def test_parse_ghidra_output_empty_functions(self, analysis_plugin: AnalysisPlugin):
        result = analysis_plugin._parse_ghidra_output(json.dumps({'functions': []}))
        assert result == []

    def test_parse_ghidra_output_invalid_json(self, analysis_plugin: AnalysisPlugin):
        from analysis.plugin import AnalysisFailedError

        with pytest.raises(AnalysisFailedError, match='Could not parse'):
            analysis_plugin._parse_ghidra_output('not valid json {{')

    def test_parse_ghidra_output_truncation(self, analysis_plugin: AnalysisPlugin):
        long_pseudo = 'x' * (analysis_plugin.max_pseudocode_length + 500)
        data = {'functions': [{'name': 'big', 'address': '0x0', 'pseudocode': long_pseudo, 'callees': []}]}
        functions = analysis_plugin._parse_ghidra_output(json.dumps(data))
        assert len(functions[0].pseudocode) <= analysis_plugin.max_pseudocode_length + len('\n/* [truncated] */')
        assert functions[0].pseudocode.endswith('/* [truncated] */')

    # ------------------------------------------------------------------
    # summarize
    # ------------------------------------------------------------------

    def test_summarize(self, analysis_plugin: AnalysisPlugin):
        schema = AnalysisPlugin.Schema(
            functions=[
                FunctionInfo(name='main', address='0x0', pseudocode='', callees=[]),
                FunctionInfo(name='helper', address='0x1', pseudocode='', callees=['main']),
            ]
        )
        summary = analysis_plugin.summarize(schema)
        assert sorted(summary) == ['helper', 'main']

    def test_summarize_empty(self, analysis_plugin: AnalysisPlugin):
        schema = AnalysisPlugin.Schema(functions=[])
        assert analysis_plugin.summarize(schema) == []

    # ------------------------------------------------------------------
    # analyze (end-to-end with mocked Docker)
    # ------------------------------------------------------------------

    def test_analyze_success(self, analysis_plugin: AnalysisPlugin, tmp_path):
        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        result_json = json.dumps(SAMPLE_RESULT)

        def fake_run_docker(file_path, output_dir):
            return _make_docker_result(result_json, output_dir)

        with patch.object(analysis_plugin, '_run_ghidra_in_docker', side_effect=fake_run_docker):
            with binary.open('rb') as fh:
                result = analysis_plugin.analyze(fh, {}, {})

        assert isinstance(result, AnalysisPlugin.Schema)
        assert len(result.functions) == 2

    def test_analyze_missing_result_file(self, analysis_plugin: AnalysisPlugin, tmp_path):
        from analysis.plugin import AnalysisFailedError

        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        def fake_run_docker(file_path, output_dir):
            # Do NOT write result.json
            return CompletedProcess(args=['entrypoint'], returncode=1, stdout='error', stderr=None)

        with patch.object(analysis_plugin, '_run_ghidra_in_docker', side_effect=fake_run_docker):
            with binary.open('rb') as fh:
                with pytest.raises(AnalysisFailedError, match='result file'):
                    analysis_plugin.analyze(fh, {}, {})

    def test_analyze_docker_timeout(self, analysis_plugin: AnalysisPlugin, tmp_path):
        from analysis.plugin import AnalysisFailedError

        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        def fake_run_docker(file_path, output_dir):
            raise AnalysisFailedError('No response from Ghidra Docker container (possible timeout)')

        with patch.object(analysis_plugin, '_run_ghidra_in_docker', side_effect=fake_run_docker):
            with binary.open('rb') as fh:
                with pytest.raises(AnalysisFailedError, match='timeout'):
                    analysis_plugin.analyze(fh, {}, {})

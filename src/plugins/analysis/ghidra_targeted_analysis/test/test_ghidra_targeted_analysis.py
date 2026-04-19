"""Tests for the ghidra_targeted_analysis plugin.

Docker / Ghidra are not available in unit-test environments, so
``_run_targeted_analysis_in_docker`` is mocked throughout.
"""

from __future__ import annotations

import json
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest

from plugins.analysis.ghidra_targeted_analysis.code.ghidra_targeted_analysis import (
    AnalysisPlugin,
    FunctionDetail,
)

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

SAMPLE_RESULT = {
    'entry_points': ['main'],
    'sensitive_vars': ['buf'],
    'call_tree': [
        {
            'name': 'main',
            'address': '0x00401000',
            'pseudocode': 'int main(void) { char buf[64]; gets(buf); return 0; }',
            'callees': ['gets'],
            'depth': 0,
            'sensitive_var_refs': ['buf'],
        },
        {
            'name': 'gets',
            'address': '0x00401080',
            'pseudocode': '',
            'callees': [],
            'depth': 1,
            'sensitive_var_refs': [],
        },
    ],
}


def _write_result(result_json: str, output_dir: str) -> CompletedProcess:
    """Write *result_json* into *output_dir*/result.json, simulating Docker."""
    (Path(output_dir) / 'result.json').write_text(result_json, encoding='utf-8')
    return CompletedProcess(args=['entrypoint'], returncode=0, stdout='', stderr=None)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestGhidraTargetedAnalysisPlugin:
    # ------------------------------------------------------------------
    # analyze() — always returns empty schema
    # ------------------------------------------------------------------

    def test_analyze_returns_empty_schema(self, analysis_plugin: AnalysisPlugin, tmp_path):
        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')
        with binary.open('rb') as fh:
            result = analysis_plugin.analyze(fh, {}, {})
        assert isinstance(result, AnalysisPlugin.Schema)
        assert result.call_tree == []
        assert result.entry_points == []

    # ------------------------------------------------------------------
    # summarize()
    # ------------------------------------------------------------------

    def test_summarize(self, analysis_plugin: AnalysisPlugin):
        schema = AnalysisPlugin.Schema(
            entry_points=['main'],
            sensitive_vars=['buf'],
            call_tree=[
                FunctionDetail(name='main', address='0x0', pseudocode='', callees=[], depth=0, sensitive_var_refs=['buf']),
                FunctionDetail(name='gets', address='0x1', pseudocode='', callees=[], depth=1, sensitive_var_refs=[]),
            ],
        )
        assert sorted(analysis_plugin.summarize(schema)) == ['gets', 'main']

    def test_summarize_empty(self, analysis_plugin: AnalysisPlugin):
        schema = AnalysisPlugin.Schema()
        assert analysis_plugin.summarize(schema) == []

    # ------------------------------------------------------------------
    # _parse_result()
    # ------------------------------------------------------------------

    def test_parse_result_basic(self, analysis_plugin: AnalysisPlugin):
        schema = analysis_plugin._parse_result(json.dumps(SAMPLE_RESULT), ['main'], ['buf'])
        assert len(schema.call_tree) == 2
        names = {f.name for f in schema.call_tree}
        assert names == {'main', 'gets'}

    def test_parse_result_sensitive_var_refs(self, analysis_plugin: AnalysisPlugin):
        schema = analysis_plugin._parse_result(json.dumps(SAMPLE_RESULT), ['main'], ['buf'])
        main_func = next(f for f in schema.call_tree if f.name == 'main')
        assert 'buf' in main_func.sensitive_var_refs

    def test_parse_result_depth(self, analysis_plugin: AnalysisPlugin):
        schema = analysis_plugin._parse_result(json.dumps(SAMPLE_RESULT), ['main'], ['buf'])
        main_func = next(f for f in schema.call_tree if f.name == 'main')
        gets_func = next(f for f in schema.call_tree if f.name == 'gets')
        assert main_func.depth == 0
        assert gets_func.depth == 1

    def test_parse_result_empty_call_tree(self, analysis_plugin: AnalysisPlugin):
        data = {'entry_points': ['main'], 'sensitive_vars': [], 'call_tree': []}
        schema = analysis_plugin._parse_result(json.dumps(data), ['main'], [])
        assert schema.call_tree == []

    def test_parse_result_invalid_json(self, analysis_plugin: AnalysisPlugin):
        from analysis.plugin import AnalysisFailedError

        with pytest.raises(AnalysisFailedError, match='Could not parse'):
            analysis_plugin._parse_result('{{not json}}', [], [])

    def test_parse_result_pseudocode_truncation(self, analysis_plugin: AnalysisPlugin):
        long_code = 'x' * (analysis_plugin.max_pseudocode_length + 1000)
        data = {
            'entry_points': ['big'],
            'sensitive_vars': [],
            'call_tree': [
                {
                    'name': 'big',
                    'address': '0x0',
                    'pseudocode': long_code,
                    'callees': [],
                    'depth': 0,
                    'sensitive_var_refs': [],
                }
            ],
        }
        schema = analysis_plugin._parse_result(json.dumps(data), ['big'], [])
        assert schema.call_tree[0].pseudocode.endswith('/* [truncated] */')

    # ------------------------------------------------------------------
    # run_targeted_analysis() — end-to-end with mocked Docker
    # ------------------------------------------------------------------

    def test_run_targeted_analysis_success(self, analysis_plugin: AnalysisPlugin, tmp_path):
        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        def fake_docker(file_path, output_dir, entry_points, sensitive_vars, max_depth):
            return _write_result(json.dumps(SAMPLE_RESULT), output_dir)

        with patch.object(analysis_plugin, '_run_targeted_analysis_in_docker', side_effect=fake_docker):
            schema = analysis_plugin.run_targeted_analysis(
                str(binary), entry_points=['main'], sensitive_vars=['buf']
            )

        assert isinstance(schema, AnalysisPlugin.Schema)
        assert len(schema.call_tree) == 2
        assert schema.entry_points == ['main']
        assert schema.sensitive_vars == ['buf']

    def test_run_targeted_analysis_missing_result_file(self, analysis_plugin: AnalysisPlugin, tmp_path):
        from analysis.plugin import AnalysisFailedError

        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        def fake_docker(file_path, output_dir, entry_points, sensitive_vars, max_depth):
            # Do NOT write result.json
            return CompletedProcess(args=['entrypoint'], returncode=1, stdout='error', stderr=None)

        with patch.object(analysis_plugin, '_run_targeted_analysis_in_docker', side_effect=fake_docker):
            with pytest.raises(AnalysisFailedError, match='result file'):
                analysis_plugin.run_targeted_analysis(str(binary), entry_points=['main'])

    def test_run_targeted_analysis_docker_timeout(self, analysis_plugin: AnalysisPlugin, tmp_path):
        from analysis.plugin import AnalysisFailedError

        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        def fake_docker(file_path, output_dir, entry_points, sensitive_vars, max_depth):
            raise AnalysisFailedError('No response from Ghidra Docker container (possible timeout)')

        with patch.object(analysis_plugin, '_run_targeted_analysis_in_docker', side_effect=fake_docker):
            with pytest.raises(AnalysisFailedError, match='timeout'):
                analysis_plugin.run_targeted_analysis(str(binary), entry_points=['main'])

    def test_params_passed_to_docker_runner(self, analysis_plugin: AnalysisPlugin, tmp_path):
        """Parameters from run_targeted_analysis() must be forwarded to the Docker runner."""
        binary = tmp_path / 'binary'
        binary.write_bytes(b'\x7fELF')

        captured: dict = {}

        def fake_docker(file_path, output_dir, entry_points, sensitive_vars, max_depth):
            captured['entry_points'] = entry_points
            captured['sensitive_vars'] = sensitive_vars
            captured['max_depth'] = max_depth
            return _write_result(json.dumps(SAMPLE_RESULT), output_dir)

        with patch.object(analysis_plugin, '_run_targeted_analysis_in_docker', side_effect=fake_docker):
            analysis_plugin.run_targeted_analysis(
                str(binary),
                entry_points=['main'],
                sensitive_vars=['buf'],
                max_depth=3,
            )

        assert captured['entry_points'] == ['main']
        assert captured['sensitive_vars'] == ['buf']
        assert captured['max_depth'] == 3

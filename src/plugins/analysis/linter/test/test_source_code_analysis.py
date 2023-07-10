from pathlib import Path

import pytest

from ..code.source_code_analysis import AnalysisPlugin

PYLINT_TEST_FILE = Path(__file__).parent / 'data' / 'linter_test_file'
NOT_A_SCRIPT_FILE = Path(__file__).parent / 'data' / 'file'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestSourceCodeAnalysis:
    def test_analyze_not_supported(self, analysis_plugin):
        with Path(NOT_A_SCRIPT_FILE).open() as f:
            result = analysis_plugin.analyze(f, {}, {})
        summary = analysis_plugin.summarize(result)

        assert summary == []
        assert result.language is None
        assert result.issues is None

    def test_analyze(self, analysis_plugin, monkeypatch):
        with Path(PYLINT_TEST_FILE).open() as f:
            result = analysis_plugin.analyze(f, {}, {})
        summary = analysis_plugin.summarize(result)

        assert set(summary) == {'has-warnings', 'python'}
        assert result is not None
        assert len(result.issues) > 0
        assert result.issues[0].type == 'warning'
        assert result.issues[0].symbol == 'unused-import'

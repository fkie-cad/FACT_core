from pathlib import Path

import pytest

from ..code.source_code_analysis import AnalysisPlugin

TEST_DATA_DIR = Path(__file__).parent / 'data'
PYLINT_TEST_FILE = TEST_DATA_DIR / 'hello_world.py'
PHP_TEST_FILE = TEST_DATA_DIR / 'hello_world.php'
JS_TEST_FILE = TEST_DATA_DIR / 'hello_world.js'
RUBY_TEST_FILE = TEST_DATA_DIR / 'hello_world.ruby'
BASH_TEST_FILE = TEST_DATA_DIR / 'hello_world.sh'
NOT_A_SCRIPT_FILE = TEST_DATA_DIR / 'file'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestSourceCodeAnalysis:
    def test_analyze_not_supported(self, analysis_plugin):
        with NOT_A_SCRIPT_FILE.open() as f:
            result = analysis_plugin.analyze(f, {}, {})
        summary = analysis_plugin.summarize(result)

        assert summary == []
        assert result.language is None
        assert result.issues is None

    @pytest.mark.parametrize(
        ('file', 'language', 'symbol'),
        [
            (PYLINT_TEST_FILE, 'python', 'unused-import'),
            (PHP_TEST_FILE, 'php', 'error'),
            (JS_TEST_FILE, 'javascript', 'no-unused-vars'),
            (RUBY_TEST_FILE, 'ruby', 'Style/FrozenStringLiteralComment'),
            (BASH_TEST_FILE, 'shell', '2050'),
        ],
    )
    def test_analyze(self, analysis_plugin, file, language, symbol):
        with file.open() as f:
            result = analysis_plugin.analyze(f, {}, {})
        summary = analysis_plugin.summarize(result)

        assert set(summary) == {'has-warnings', language}
        assert result is not None
        assert len(result.issues) > 0
        assert result.issues[0].symbol == symbol

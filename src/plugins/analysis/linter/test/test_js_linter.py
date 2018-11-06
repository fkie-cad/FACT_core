import pytest

from ..internal.js_linter import JavaScriptLinter

MOCK_RESPONSE = '''/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 10, col 14, Missing "use strict" statement. (E007)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 10, col 91, Missing semicolon. (W033)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 10, col 443, Expected '===' and instead saw '=='. (W116)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 10, col 565, Missing semicolon. (E058)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 10, col 565, Expected an identifier and instead saw '='. (E030)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 10, col 565, Expected an assignment or function call and instead saw an expression. (W030)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 10, col 725, 'i' was used before it was defined. (W003)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 10, col 837, 'exports' is defined but never used. (W098)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 54, col 38, Expected a conditional expression and instead saw an assignment. (W084)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 56, col 16, 'i' is already defined. (W004)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 153, col 15, Misleading line break before '+'; readers may interpret this as an expression boundary. (W014)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 231, col 1, The body of a for in should be wrapped in an if statement to filter unwanted properties from the prototype. (W089)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 414, col 24, Unexpected use of '<<'. (W016)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 1429, col 29, Functions declared within loops referencing an outer scoped variable may lead to confusing semantics. (conversions) (W083)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 4739, col 37, Empty block. (W035)
/home/dorp/work/FACT_core/src/web_interface/static/Chart.js: line 10, col 128, 'define' is not defined. (W117)

16 errors
'''


@pytest.fixture(scope='function')
def stub_linter():
    return JavaScriptLinter()


def test_do_analysis(stub_linter, monkeypatch):
    monkeypatch.setattr('plugins.analysis.linter.internal.js_linter.execute_shell_command', lambda command: MOCK_RESPONSE)
    result = stub_linter.do_analysis('any/path')
    assert 'full' in result
    assert len(result['full']) == 16
    assert result['full'][0] == {
        'message': 'Missing "use strict" statement',
        'line': 10,
        'column': 14,
        'symbol': 'E007'
    }

import pytest

from ..internal.js_linter import JavaScriptLinter

MOCK_RESPONSE = '''/any/path: line 1, col 29, Any Message. (conversions) (W083)
/any/path: line 10, col 14, Missing "use strict" statement. (E007)
/any/path: line 10, col 91, Missing semicolon. (W033)
/any/path: line 10, col 128, 'define' is not defined. (W117)
/any/path: line 10, col 443, Expected '===' and instead saw '=='. (W116)
/any/path: line 10, col 565, Missing semicolon. (E058)
/any/path: line 10, col 565, Expected an identifier and instead saw '='. (E030)
/any/path: line 10, col 565, Expected an assignment or function call and instead saw an expression. (W030)
/any/path: line 10, col 725, 'i' was used before it was defined. (W003)
/any/path: line 10, col 837, 'exports' is defined but never used. (W098)
/any/path: line 54, col 38, Expected a conditional expression and instead saw an assignment. (W084)
/any/path: line 56, col 16, 'i' is already defined. (W004)
/any/path: line 153, col 15, Misleading line break before '+'; readers may interpret this as an expression boundary. (W014)
/any/path: line 231, col 1, The body of a for in should be wrapped in an if statement to filter unwanted properties from the prototype. (W089)
/any/path: line 414, col 24, Unexpected use of '<<'. (W016)
/any/path/: line 752, col 94, This line contains stuff: http://weblink/ (W125)
/any/path: line 4739, col 37, Empty block. (W035)

17 errors
'''


@pytest.fixture(scope='function')
def stub_linter():
    return JavaScriptLinter()


def test_do_analysis(stub_linter, monkeypatch):
    monkeypatch.setattr('plugins.analysis.linter.internal.js_linter.execute_shell_command', lambda command: MOCK_RESPONSE)
    result = stub_linter.do_analysis('any/path')
    assert result
    assert len(result) == 17
    assert result[0] == {
        'message': 'Any Message. (conversions)',
        'line': 1,
        'column': 29,
        'symbol': 'W083'
    }


def test_parse_linter_output_bad_line(stub_linter, monkeypatch):
    bad_line = '/any/path: line1, col 37, Empty block. W035\n\n1 error\n'
    monkeypatch.setattr('plugins.analysis.linter.internal.js_linter.execute_shell_command', lambda command: bad_line)
    result = stub_linter.do_analysis('any/path')
    assert not result

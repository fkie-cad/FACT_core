from subprocess import CompletedProcess

from ..internal.linters import run_pylint

MOCK_RESPONSE = '''[
    {
        "type": "warning",
        "module": "plugins.analysis.linter.test.test_js_linter",
        "obj": "test_do_analysis",
        "line": 32,
        "column": 21,
        "path": "test/test_js_linter.py",
        "symbol": "redefined-outer-name",
        "message": "Redefining name 'stub_linter' from outer scope (line 28)",
        "message-id": "W0621",
    }
]
'''

BAD_RESPONSE = '''Usage:  pylint [options] modules_or_packages

  Check that module(s) satisfy a coding standard (and more !).

    pylint --help

  Display this help message and exit.

    pylint --help-msg <msg-id>[,<msg-id>]

  Display help messages about given message identifiers and exit.


pylint: error: no such option: -a
'''


def test_do_analysis(monkeypatch):
    monkeypatch.setattr(
        'plugins.analysis.linter.internal.linters.subprocess.run',
        lambda *_,
        **__: CompletedProcess('DONT_CARE', 0, stdout=MOCK_RESPONSE)
    )
    result = run_pylint('any/path')

    assert len(result[0].keys()) == 5
    assert result[0]['type'] == 'warning'


def test_do_analysis_bad_invokation(monkeypatch):
    monkeypatch.setattr(
        'plugins.analysis.linter.internal.linters.subprocess.run',
        lambda *_,
        **__: CompletedProcess('DONT_CARE', 1, stdout=BAD_RESPONSE)
    )
    result = run_pylint('any/path')
    assert not result

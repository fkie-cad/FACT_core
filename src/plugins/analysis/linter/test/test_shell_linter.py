from subprocess import CompletedProcess

from ..internal.linters import run_shellcheck

MOCK_RESPONSE = """[
    {
        "file": "src/install/pre_install.sh",
        "line": 8,
        "endLine": 8,
        "column": 30,
        "endColumn": 30,
        "level": "warning",
        "code": 2166,
        "message": "Prefer [ p ] || [ q ] as [ p -o q ] is not well defined."
    },
    {
        "file": "src/install/pre_install.sh",
        "line": 12,
        "endLine": 12,
        "column": 47,
        "endColumn": 47,
        "level": "warning",
        "code": 2046,
        "message": "Quote this to prevent word splitting."
    },
    {
        "file": "src/install/pre_install.sh",
        "line": 44,
        "endLine": 44,
        "column": 25,
        "endColumn": 25,
        "level": "info",
        "code": 2086,
        "message": "Double quote to prevent globbing and word splitting."
    }
]"""

BAD_RESPONSE = """any/path: any/path: openBinaryFile: does not exist (No such file or directory)
[]
"""


def test_do_analysis(monkeypatch):
    monkeypatch.setattr(
        'plugins.analysis.linter.internal.linters.subprocess.run',
        lambda *_, **__: CompletedProcess('DONT_CARE', 0, stdout=MOCK_RESPONSE),
    )
    result = run_shellcheck('any/path')

    assert result
    assert len(result) == 2, 'info issue should be discarded'

    assert len(result[0].keys()) == 5
    assert result[0]['type'] == 'warning'


def test_do_analysis_bad_invokation(monkeypatch):
    monkeypatch.setattr(
        'plugins.analysis.linter.internal.linters.subprocess.run',
        lambda *_, **__: CompletedProcess('DONT_CARE', 1, stdout=BAD_RESPONSE),
    )
    result = run_shellcheck('any/path')
    assert 'full' not in result


def test_do_analysis_bad_status_code(monkeypatch):
    monkeypatch.setattr(
        'plugins.analysis.linter.internal.linters.subprocess.run',
        lambda *_, **__: CompletedProcess('DONT_CARE', 2, stdout=MOCK_RESPONSE),
    )
    result = run_shellcheck('any/path')
    assert 'full' not in result

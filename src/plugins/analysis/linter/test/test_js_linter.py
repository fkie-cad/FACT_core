from pathlib import Path

import pytest

from ..internal.js_linter import JavaScriptLinter


@pytest.fixture(scope='function')
def stub_linter():
    return JavaScriptLinter()


def run_docker_container_stub(*_, **__):
    stdout = r'''[
    {
        "filePath": "test_file_path.js",
        "messages": [
            {
                "ruleId": "no-unused-vars",
                "severity": 2,
                "message": "'x' is assigned a value but never used.",
                "line": 1,
                "column": 5,
                "nodeType": "Identifier",
                "messageId": "unusedVar",
                "endLine": 1,
                "endColumn": 6
            }
        ],
        "errorCount": 1,
        "fatalErrorCount": 0,
        "warningCount": 0,
        "fixableErrorCount": 0,
        "fixableWarningCount": 0,
        "source": "var x = 5\nalert( 'Hello, world!' );\n",
        "usedDeprecatedRules": []
    }
]'''
    return stdout, 1


def test_do_analysis(stub_linter, monkeypatch):
    monkeypatch.setattr('plugins.analysis.linter.internal.js_linter.run_docker_container', run_docker_container_stub)
    result = stub_linter.do_analysis('test_file_path.js')
    assert result
    assert len(result) == 1
    assert result[0] == {
        'symbol': 'no-unused-vars',
        'message': "'x' is assigned a value but never used.",
        'line': 1,
        'column': 5,
    }


def test_do_analysis_with_docker(stub_linter):
    hello_world_js = Path(__file__).parent / 'data/hello_world.js'
    issues = stub_linter.do_analysis(hello_world_js)
    # We mostly don't care about the output we just want no exceptions
    assert len(issues) != 0

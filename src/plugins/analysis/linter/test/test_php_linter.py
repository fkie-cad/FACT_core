from subprocess import CompletedProcess

from ..internal.linters import run_phpstan

MOCK_RESPONSE = '''{
  "totals": {
    "errors": 0,
    "file_errors": 1
  },
  "files": {
    "/app/input.php": {
      "errors": 1,
      "messages": [
        {
          "message": "Parameter $date of method HelloWorld::sayHello() has invalid type DateTimeImutable.",
          "line": 5,
          "ignorable": true
        }
      ]
    }
  },
  "errors": []
}
'''


def test_do_analysis(monkeypatch):
    monkeypatch.setattr('plugins.analysis.linter.internal.linters.subprocess.run', lambda *_, **__: CompletedProcess('args', 0, stdout=MOCK_RESPONSE))
    result = run_phpstan('any/path')

    assert len(result) == 1
from pathlib import Path
from subprocess import CompletedProcess

from ..internal.linters import run_rubocop

MOCK_RESPONSE = '''
{
  "metadata": {
    "rubocop_version": "0.52.1",
    "ruby_engine": "ruby",
    "ruby_version": "2.7.0",
    "ruby_patchlevel": "0",
    "ruby_platform": "x86_64-linux-gnu"
  },
  "files": [
    {
      "path": "hello_world.ruby",
      "offenses": [
        {
          "severity": "convention",
          "message": "Style/StringLiterals: Prefer single-quoted strings when you don't need string interpolation or special symbols.",
          "cop_name": "Style/StringLiterals",
          "corrected": false,
          "location": {
            "start_line": 1,
            "start_column": 6,
            "last_line": 1,
            "last_column": 18,
            "length": 13,
            "line": 1,
            "column": 6
          }
        }
      ]
    }
  ],
  "summary": {
    "offense_count": 1,
    "target_file_count": 1,
    "inspected_file_count": 1
  }
}
'''  # noqa: E501


def test_do_analysis(monkeypatch):
    monkeypatch.setattr(
        'plugins.analysis.linter.internal.linters.run_docker_container',
        lambda *_, **__: CompletedProcess('args', 0, stdout=MOCK_RESPONSE),
    )
    result = run_rubocop('any/path')

    assert len(result) == 1


def test_do_analysis_unmocked():
    # Older versions of rubocop ignored files that didn't have an .ruby extension
    hello_world_ruby = Path(__file__).parent / 'data/hello_world_ruby'
    result = run_rubocop(str(hello_world_ruby))

    assert len(result) == 2  # noqa: PLR2004

    hello_world_dot_ruby = Path(__file__).parent / 'data/hello_world.ruby'
    result = run_rubocop(str(hello_world_dot_ruby))

    assert len(result) == 2  # noqa: PLR2004

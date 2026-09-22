import io
from pathlib import Path

import pytest

from ..code.filepaths import AnalysisPlugin, _remove_duplicate_paths, _remove_quotes

TEST_DATA_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_additional_rules(analysis_plugin):
    file_path = str(TEST_DATA_DIR / 'testfile')
    result = analysis_plugin.analyze(io.FileIO(file_path), {}, {})
    summary = analysis_plugin.summarize(result)
    assert sorted(result.filepaths) == ['./do_something.sh', '/etc/passwd', '~/.ssh/id_rsa']
    assert summary == ['filepaths']


@pytest.mark.parametrize(
    ('path_list', 'expected'),
    [
        ([], []),
        (
            [('/foo/bar.sh', 0), ('/bar.sh', 4), ('/baz', 23), ('../baz', 21)],
            ['../baz', '/foo/bar.sh'],
        ),
        (
            [('/foo/bar.sh', 0), ('/bar.sh', 4), ('/baz', 23), ('../baz', 21), ('/bar.sh', 42)],
            ['../baz', '/bar.sh', '/foo/bar.sh'],
        ),
    ],
)
def test_remove_duplicate_paths(path_list, expected):
    assert sorted(_remove_duplicate_paths(path_list)) == expected


def test_remove_quotes():
    assert _remove_quotes('"/foo/bar.sh"') == '/foo/bar.sh'
    assert _remove_quotes("'/foo/bar.sh'") == '/foo/bar.sh'

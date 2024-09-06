from pathlib import Path

import pytest

from ..code.ipc_analyzer import AnalysisPlugin

TEST_DIR = Path(__file__).parent / 'data'

EXPECTED_SYSTEM_RESULT = {
    'calls': [
        {'arguments': [''], 'name': 'system', 'target': 'whoami'},
        {'arguments': ['-l'], 'name': 'system', 'target': 'ls'},
        {'arguments': ['hello'], 'name': 'system', 'target': 'echo'},
        {'arguments': [''], 'name': 'system', 'target': 'id'},
        {'arguments': [''], 'name': 'system', 'target': 'pwd'},
    ]
}

EXPECTED_WRITE_RESULT = {
    'calls': [
        {'arguments': ['', ['O_RDWR | O_CREAT'], ['0666L']], 'name': 'open', 'target': 'data.dat'},
        {
            'arguments': [
                '',
                ['Now is the winter of our discontent\\nMade ' 'glorious summer by this sun of York\\n'],
                [77],
            ],
            'name': 'write',
            'target': 'data.dat',
        },
    ]
}


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
@pytest.mark.parametrize(
    ('test_file', 'expected_result', 'expected_summary'),
    [
        ('ipc_system_test_bin', EXPECTED_SYSTEM_RESULT, ['system']),
        ('ipc_shared_files_test_bin', EXPECTED_WRITE_RESULT, ['open', 'write']),
    ],
)
def test_ipc_analyze_summary(analysis_plugin, test_file, expected_result, expected_summary):
    with (TEST_DIR / test_file).open('rb') as fp:
        result = analysis_plugin.analyze(fp, {}, {})
    as_dict = result.model_dump()
    assert as_dict == expected_result
    summary = analysis_plugin.summarize(result)
    assert summary == expected_summary

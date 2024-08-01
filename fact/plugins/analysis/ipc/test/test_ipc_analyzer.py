from pathlib import Path

import pytest

from fact.objects.file import FileObject

from ..code.ipc_analyzer import AnalysisPlugin

TEST_DIR = Path(__file__).parent / 'data'


EXPECTED_SYSTEM_RESULT = {
    'whoami': [{'type': 'system', 'arguments': ['']}],
    'ls': [{'type': 'system', 'arguments': ['-l']}],
    'echo': [{'type': 'system', 'arguments': ['hello']}],
    'id': [{'type': 'system', 'arguments': ['']}],
    'pwd': [{'type': 'system', 'arguments': ['']}],
}

EXPECTED_WRITE_RESULT = {
    'data.dat': [
        {'type': 'open', 'arguments': ['', ['O_RDWR | O_CREAT'], ['0666L']]},
        {
            'type': 'write',
            'arguments': [
                '',
                ['Now is the winter of our discontent\\nMade glorious summer by this sun of York\\n'],
                [77],
            ],
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
def test_ipc_system(analysis_plugin, test_file, expected_result, expected_summary):
    test_object = FileObject(file_path=str((TEST_DIR / test_file).resolve()))
    result = analysis_plugin.process_object(test_object)
    assert result.processed_analysis['ipc_analyzer']['full']['ipcCalls'] == expected_result
    assert result.processed_analysis['ipc_analyzer']['summary'] == expected_summary

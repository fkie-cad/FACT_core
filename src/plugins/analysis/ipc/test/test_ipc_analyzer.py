from pathlib import Path

import pytest

from objects.file import FileObject

from ..code.ipc_analyzer import AnalysisPlugin

TEST_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(dict(plugin_class=AnalysisPlugin))
class TestAnalysisPluginIpcAnalyzer:
    def test_ipc_system(self, analysis_plugin):
        expected_result = {
            'whoami': [{'type': 'system', 'arguments': ['']}],
            'ls': [{'type': 'system', 'arguments': ['-l']}],
            'echo': [{'type': 'system', 'arguments': ['hello']}],
            'id': [{'type': 'system', 'arguments': ['']}],
            'pwd': [{'type': 'system', 'arguments': ['']}],
        }

        self._do_ipc_analysis(analysis_plugin, 'ipc_system_test_bin', expected_result)

        expected_result = {
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

        self._do_ipc_analysis(analysis_plugin, 'ipc_shared_files_test_bin', expected_result)

    def _do_ipc_analysis(self, analysis_plugin, test_file, expected_result):
        test_object = FileObject(file_path=str((TEST_DIR / test_file).resolve()))
        result = analysis_plugin.process_object(test_object)
        assert result.processed_analysis['ipc_analyzer']['full']['ipcCalls'] == expected_result

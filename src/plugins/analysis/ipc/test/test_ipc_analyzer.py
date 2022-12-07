from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest
from objects.file import FileObject
from ..code.ipc_analyzer import AnalysisPlugin
from pathlib import Path

TEST_DIR = Path(__file__).parent / 'data'
 
class TestAnalysisPluginIpcAnalyzer(AnalysisPluginTest):
 
    PLUGIN_NAME = 'ipc_analyzer'
    PLUGIN_CLASS = AnalysisPlugin

    def _do_ipc_analysis(self, test_file, expected_result):
        test_object = FileObject(file_path=str((TEST_DIR / test_file).resolve()))
        result = self.analysis_plugin.process_object(test_object)
        assert result.processed_analysis[self.PLUGIN_NAME]['full']['ipcCalls'] == expected_result
 
    def test_ipc_system(self):
        expected_result = {'echo': [{'type': 'system', 'arguments': ['hello']}],'id': [{'type': 'system', 'arguments': ['']}], 'ls': [{'type': 'system', 'arguments': ['-l']}], 'pwd': [{'type': 'system', 'arguments': ['']}],'whoami': [{'type': 'system', 'arguments': ['']}]}
        self._do_ipc_analysis('ipc_system_test_bin', expected_result)

        expected_result = {'data.dat': [{'type': 'open', 'arguments': ['', 'O_RDWR | O_CREAT', '0666L']}, {'type': 'write', 'arguments': ['', 'Now is the winter of our discontent\\nMade glorious summer by this sun of York\\n', 77]}]}
        self._do_ipc_analysis('ipc_shared_files_test_bin', expected_result)
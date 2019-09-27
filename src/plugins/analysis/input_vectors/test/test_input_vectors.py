from pathlib import Path

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest

from ..code.input_vectors import AnalysisPlugin

TEST_FILE_DIR = Path(__file__).parent / 'data'


class AnalysisPluginTestInputVectors(AnalysisPluginTest):

    PLUGIN_NAME = 'input_vectors'

    def setUp(self):
        super().setUp()
        config = self.init_basic_config()
        self.analysis_plugin = AnalysisPlugin(self, config=config)

    def test_process_object_inputs(self):
        result = self.assert_process_object('test_fgets.elf')
        assert 'file' in result['full']['inputs']
        assert result['full']['inputs']['file'][0]['name'] == 'fgets'

    def test_process_object_domains(self):
        result = self.assert_process_object('test_domain.elf')
        assert result['full']['domains'][0] == 'http://foo.bar'

    def assert_process_object(self, test_file_name: str) -> dict:
        test_file = TEST_FILE_DIR / test_file_name
        assert test_file.is_file(), 'test file is missing'
        fo = FileObject(file_path=str(test_file))
        result = self.analysis_plugin.process_object(fo)
        assert 'input_vectors' in result.processed_analysis
        assert result.processed_analysis['input_vectors']['full']
        return result.processed_analysis['input_vectors']

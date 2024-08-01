from pathlib import Path

import pytest

from fact.objects.file import FileObject

from ..code.input_vectors import AnalysisPlugin

TEST_FILE_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginInputVectors:
    def test_process_object_inputs(self, analysis_plugin):
        result = self.assert_process_object(analysis_plugin, 'test_fgets.elf')
        assert 'file' in result['full']['inputs']
        assert result['full']['inputs']['file'][0]['name'] == 'fgets'

    def test_process_object_domains(self, analysis_plugin):
        result = self.assert_process_object(analysis_plugin, 'test_domain.elf')
        assert result['full']['domains'][0] == 'http://foo.bar'

    def assert_process_object(self, analysis_plugin, test_file_name: str) -> dict:
        test_file = TEST_FILE_DIR / test_file_name
        assert test_file.is_file(), 'test file is missing'
        fo = FileObject(file_path=str(test_file))
        result = analysis_plugin.process_object(fo)
        assert 'input_vectors' in result.processed_analysis
        assert result.processed_analysis['input_vectors']['full']
        return result.processed_analysis['input_vectors']

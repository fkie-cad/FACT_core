from pathlib import Path

import pytest

from ..code.input_vectors import AnalysisPlugin

TEST_FILE_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestAnalysisPluginInputVectors:
    def test_process_object_inputs(self, analysis_plugin):
        test_file = TEST_FILE_DIR / 'test_fgets.elf'
        with test_file.open() as fp:
            result = analysis_plugin.analyze(fp, {}, {})
        assert result.inputs.file is not None
        assert result.inputs.file[0].name == 'fgets'

    def test_process_object_domains(self, analysis_plugin):
        test_file = TEST_FILE_DIR / 'test_domain.elf'
        with test_file.open() as fp:
            result = analysis_plugin.analyze(fp, {}, {})
        assert result.domains[0] == 'http://foo.bar'

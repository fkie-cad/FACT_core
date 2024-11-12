import pytest

from test.common_helper import get_test_data_dir

from ..code.binwalk import AnalysisPlugin

TEST_FILE = get_test_data_dir() / 'container' / 'test.zip'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestPluginBinwalk:
    def test_signature_analysis(self, analysis_plugin):
        assert TEST_FILE.is_file(), 'test file is missing'
        with TEST_FILE.open() as fp:
            result = analysis_plugin.analyze(fp, {}, {})
        assert len(result.signature_analysis) > 0, 'no binwalk signature analysis found'
        assert 'Zip archive data' in result.signature_analysis[0].description, 'no valid binwalk signature analysis'

    def test_entropy_graph(self, analysis_plugin):
        assert TEST_FILE.is_file(), 'test file is missing'
        with TEST_FILE.open() as fp:
            result = analysis_plugin.analyze(fp, {}, {})
        assert len(result.entropy_analysis_graph) > 0, 'no binwalk entropy graph found'

    def test_summary(self, analysis_plugin):
        with TEST_FILE.open() as fp:
            test_result = analysis_plugin.analyze(fp, {}, {})
        summary = analysis_plugin.summarize(test_result)
        for line in summary:
            assert line in {'Zip archive data', 'End of Zip archive'}

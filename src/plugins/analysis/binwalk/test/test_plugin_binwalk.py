import string

import pytest

from objects.file import FileObject
from test.common_helper import get_test_data_dir

from ..code.binwalk import AnalysisPlugin

TEST_OUTPUT = '''
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Microsoft executable, portable (PE)
106008        0x19E18         XML document, version: "1.0"
113771        0x1BC6B         Zip archive data, at least v2.0 to extract, compressed size: 47799, uncompressed size: 119688, name: PH1BXRM_AM_000803003938.dat
2752561       0x2A0031        Falling entropy edge (0.026681)
12226608      0xBA9030        End of Zip archive, footer length: 22
'''  # noqa: E501


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
class TestPluginBinwalk:
    def test_signature_analysis(self, analysis_plugin):
        test_file = FileObject(file_path=f'{get_test_data_dir()}/container/test.zip')
        processed_file = analysis_plugin.process_object(test_file)
        results = processed_file.processed_analysis[analysis_plugin.NAME]
        assert len(results['signature_analysis']) > 0, 'no binwalk signature analysis found'
        assert 'DECIMAL' in results['signature_analysis'], 'no valid binwalk signature analysis'

    def test_entropy_graph(self, analysis_plugin):
        test_file = FileObject(file_path=f'{get_test_data_dir()}/container/test.zip')
        processed_file = analysis_plugin.process_object(test_file)
        results = processed_file.processed_analysis[analysis_plugin.NAME]
        assert len(results['entropy_analysis_graph']) > 0, 'no binwalk entropy graph found'

    def test_summary(self, analysis_plugin):
        summary = analysis_plugin._extract_summary(TEST_OUTPUT)
        for x in summary:
            assert x in ['Microsoft executable', 'XML document', 'Zip archive data', 'End of Zip archive']

    def test_iterate_valid_signature_lines(self, analysis_plugin):
        result = list(analysis_plugin._iterate_valid_signature_lines(TEST_OUTPUT.splitlines()))
        assert len(result) == 5  # noqa: PLR2004
        assert all(line[0] in string.digits for line in result)
        assert result[0] == '0             0x0             Microsoft executable, portable (PE)'

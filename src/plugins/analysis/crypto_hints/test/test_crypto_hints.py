from pathlib import Path

from objects.file import FileObject
from test.unit.analysis.analysis_plugin_test_class import AnalysisPluginTest  # pylint: disable=wrong-import-order

from ..code.crypto_hints import AnalysisPlugin

TEST_DATA_DIR = Path(__file__).parent / 'data'


class TestAnalysisPluginCryptoHints(AnalysisPluginTest):

    PLUGIN_NAME = 'crypto_hints'
    PLUGIN_CLASS = AnalysisPlugin

    def test_basic_scan_feature(self):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'CRC32_table'))
        processed_file = self.analysis_plugin.process_object(test_file)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]
        assert 'CRC32_table' in result

    def test_additional_rules(self):
        test_file = FileObject(file_path=str(TEST_DATA_DIR / 'additional_rules_test_file'))
        processed_file = self.analysis_plugin.process_object(test_file)
        result = processed_file.processed_analysis[self.PLUGIN_NAME]
        for rule in [
            'secp256r1',
            'AES_Constants',
            'SMIME_IDs',
            'Tiger_Hash_Constants',
            'camellia_constants',
            'present_cipher',
        ]:
            assert rule in result

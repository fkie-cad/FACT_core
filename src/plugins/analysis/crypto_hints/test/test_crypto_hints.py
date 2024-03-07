import io
from pathlib import Path

import pytest

from ..code.crypto_hints import AnalysisPlugin

TEST_DATA_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_additional_rules(analysis_plugin):
    file_path = str(TEST_DATA_DIR / 'additional_rules_test_file')
    result = analysis_plugin.analyze(io.FileIO(file_path), {}, {})
    summary = analysis_plugin.summarize(result)
    for rule in [
        'secp256r1',
        'AES_Constants',
        'SMIME_IDs',
        'Tiger_Hash_Constants',
        'camellia_constants',
        'present_cipher',
    ]:
        assert rule in summary


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_basic_scan_feature(analysis_plugin):
    file_path = str(TEST_DATA_DIR / 'CRC32_table')
    result = analysis_plugin.analyze(io.FileIO(file_path), {}, {})
    summary = analysis_plugin.summarize(result)
    assert 'CRC32_table' in summary

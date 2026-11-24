from io import FileIO
from pathlib import Path

import pytest

from plugins.analysis.coderec.code.coderec import AnalysisPlugin

TEST_DATA_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_basic_scan_feature(analysis_plugin, monkeypatch):
    monkeypatch.setattr('plugins.analysis.coderec.code.coderec.MIN_SIZE', 1024)  # test file is very small
    test_file = FileIO(TEST_DATA_DIR / 'fib.mips.bin')
    result = analysis_plugin.analyze(test_file, {}, {})
    assert len(result.regions) == 2
    region_by_type = {r.type: r for r in result.regions}
    assert 'MIPSeb' in region_by_type
    assert '_zero' in region_by_type
    assert region_by_type['MIPSeb'].total_size == 2048
    assert result.architecture == 'MIPSeb'

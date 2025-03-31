from io import FileIO
from pathlib import Path

import pytest

from plugins.analysis.coderec.code.coderec import AddressRange, AnalysisPlugin, _merge_overlapping_regions

TEST_DATA_DIR = Path(__file__).parent / 'data'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_basic_scan_feature(analysis_plugin):
    test_file = FileIO(TEST_DATA_DIR / 'fib.mips.bin')
    result = analysis_plugin.analyze(test_file, {}, {})
    assert len(result.regions) == 2
    region_by_type = {r.type: r for r in result.regions}
    assert 'MIPSeb' in region_by_type
    assert '_zero' in region_by_type
    assert region_by_type['MIPSeb'].total_size == 3072
    assert result.architecture == 'MIPSeb'


def test_merge_overlapping_regions():
    regions = {
        'foo': [
            AddressRange(start=7000, end=8000, size=1000),
            AddressRange(start=0000, end=1000, size=1000),
            AddressRange(start=9000, end=10000, size=1000),
            AddressRange(start=1000, end=3000, size=2000),
            AddressRange(start=5000, end=7000, size=2000),
            AddressRange(start=3000, end=4000, size=1000),
        ]
    }
    _merge_overlapping_regions(regions)

    result = sorted(regions['foo'], key=lambda r: r.start)
    assert len(result) == 3

    assert result[0].start == 0
    assert result[0].end == 4000
    assert result[0].size == 4000

    assert result[1].start == 5000
    assert result[1].end == 8000
    assert result[1].size == 3000

    assert result[2].start == 9000
    assert result[2].end == 10000
    assert result[2].size == 1000

import io
from pathlib import Path

import pytest

from ..code.device_tree import AnalysisPlugin

TEST_DATA = Path(__file__).parent.parent / 'test/data'
TEST_FILE = TEST_DATA / 'device_tree.dtb'
TEST_EMBEDDED = TEST_DATA / 'dt_embed_test.dtb'
TEST_IMAGE = TEST_DATA / 'dtb_inside.image'
TEST_FP = TEST_DATA / 'false_positive.rnd'
TEST_BROKEN = TEST_DATA / 'broken.dtb'


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
def test_analyze(analysis_plugin):
    result = analysis_plugin.analyze(io.FileIO(TEST_FILE), {}, {})
    summary = analysis_plugin.summarize(result)

    assert len(result.device_trees) == 1
    assert result.device_trees[0].model == 'Manufac XYZ1234ABC'
    assert summary == ['Manufac XYZ1234ABC']


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
@pytest.mark.parametrize('file', [TEST_EMBEDDED, TEST_IMAGE])
def test_multiple_device_trees(file, analysis_plugin):
    result = analysis_plugin.analyze(io.FileIO(file), {}, {})
    assert len(result.device_trees) == 2
    for device_tree in result.device_trees:
        assert 'foo = "bar";' in device_tree.string
        assert device_tree.header.version == 17
        assert device_tree.model in ['DeviceTreeTest-1', 'FooBar 1.0']


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
@pytest.mark.parametrize('file', [TEST_FP, TEST_BROKEN])
def test_no_device_trees(file, analysis_plugin):
    result = analysis_plugin.analyze(io.FileIO(file), {}, {})
    summary = analysis_plugin.summarize(result)
    assert result.device_trees == []
    assert summary == []


@pytest.mark.AnalysisPluginTestConfig(plugin_class=AnalysisPlugin)
@pytest.mark.parametrize(
    ('input_dts', 'expected_result'),
    [
        ('', ''),
        ('data = [01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef];', 'data = (BINARY DATA ...);'),
        ('data = <0x01 0x2345 0x67 0x89 0xabcdef 0x1234 0x56 0x78 0x90 0xab 0xcd>;', 'data = (BINARY DATA ...);'),
        ('data = [01 23 45 67];', 'data = [01 23 45 67];'),  # short entries should not be replaced
        ('data = <0x01 0x2345 0x67>;', 'data = <0x01 0x2345 0x67>;'),  # short entries should not be replaced
    ],
)
def test_replace_binary_data(analysis_plugin, input_dts, expected_result):
    assert analysis_plugin.replace_binary_data(input_dts) == expected_result

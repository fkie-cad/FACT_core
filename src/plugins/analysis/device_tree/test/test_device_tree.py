from pathlib import Path

import pytest

from objects.file import FileObject

from ..code.device_tree import AnalysisPlugin
from ..internal.device_tree_utils import dump_device_trees

TEST_DATA = Path(__file__).parent.parent / 'test/data'
TEST_FILE = TEST_DATA / 'device_tree.dtb'
TEST_EMBEDDED = TEST_DATA / 'dt_embed_test.dtb'
TEST_IMAGE = TEST_DATA / 'dtb_inside.image'
TEST_FP = TEST_DATA / 'false_positive.rnd'
TEST_BROKEN = TEST_DATA / 'broken.dtb'


@pytest.mark.AnalysisPluginClass.with_args(AnalysisPlugin)
def test_process_object(analysis_plugin):
    test_object = FileObject()
    test_object.processed_analysis['file_type'] = {'mime': 'linux/device-tree'}
    test_object.binary = TEST_FILE.read_bytes()
    test_object.file_path = str(TEST_FILE)
    processed_object = analysis_plugin.process_object(test_object)
    result = processed_object.processed_analysis[analysis_plugin.NAME]

    assert len(result['device_trees']) == 1
    assert result['device_trees'][0]['model'] == 'Manufac XYZ1234ABC'
    assert result['summary'] == ['Manufac XYZ1234ABC']


@pytest.mark.parametrize('file', [TEST_EMBEDDED, TEST_IMAGE])
def test_dump_device_trees(file):
    result = dump_device_trees(file.read_bytes())
    assert len(result) == 2
    for dt_dict in result:
        assert 'foo = "bar";' in dt_dict['device_tree']
        assert dt_dict['header']['version'] == 17
        assert dt_dict['model'] in ['DeviceTreeTest-1', 'FooBar 1.0']


@pytest.mark.parametrize('file', [TEST_FP, TEST_BROKEN])
def test_no_results(file):
    result = dump_device_trees(file.read_bytes())
    assert len(result) == 0

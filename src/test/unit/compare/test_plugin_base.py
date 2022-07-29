# pylint: disable=no-self-use
import pytest

from compare.PluginBase import CompareBasePlugin as ComparePlugin
from compare.PluginBase import _get_unmatched_dependencies
from test.common_helper import CommonDatabaseMock, create_test_firmware  # pylint: disable=wrong-import-order

fw_one = create_test_firmware(device_name='dev_1', all_files_included_set=True)
fw_two = create_test_firmware(device_name='dev_2', bin_path='container/test.7z', all_files_included_set=True)
fw_three = create_test_firmware(device_name='dev_3', bin_path='container/test.cab', all_files_included_set=True)


# When needed to be more complex take inspiration from the fixture
# 'analysis_plugin' in conftest.py
@pytest.fixture
def compare_plugin(monkeypatch, cfg_tuple):
    yield ComparePlugin(view_updater=CommonDatabaseMock())


# TODO is this needed?!
@pytest.mark.cfg_defaults(
    {
        'expert-settings': {
            'ssdeep-ignore': '80',
        },
    }
)
class TestPluginBase:
    def test_compare_missing_dep(self, compare_plugin):
        compare_plugin.DEPENDENCIES = ['test_ana']
        fw_one.processed_analysis['test_ana'] = {}
        result = compare_plugin.compare([fw_one, fw_two])
        assert result == {
            'Compare Skipped': {'all': 'Required analysis not present: test_ana'}
        }, 'missing dep result not correct'

    def test_compare(self, compare_plugin):
        result = compare_plugin.compare([fw_one, fw_two])
        assert result == {'dummy': {'all': 'dummy-content', 'collapse': False}}, 'result not correct'


class MockFileObject:
    def __init__(self, processed_analysis_list):
        self.processed_analysis = processed_analysis_list


@pytest.mark.parametrize(
    'fo_list, dependencies, expected_output',
    [
        ([MockFileObject([])], ['a'], {'a'}),
        ([MockFileObject(['a'])], ['a'], set()),
        ([MockFileObject(['a', 'b'])], ['a', 'b', 'c', 'd'], {'c', 'd'}),
        ([MockFileObject(['b']), MockFileObject(['a'])], ['a', 'b'], {'a', 'b'}),
    ],
)
def test_get_unmatched_dependencies(fo_list, dependencies, expected_output):
    assert _get_unmatched_dependencies(fo_list, dependencies) == expected_output

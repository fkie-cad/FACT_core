from unittest import mock

import pytest

from compare.PluginBase import CompareBasePlugin as ComparePlugin
from compare.PluginBase import _get_unmatched_dependencies
from test.unit.compare.compare_plugin_test_class import ComparePluginTest  # pylint: disable=wrong-import-order


class TestComparePluginBase(ComparePluginTest):

    # This name must be changed according to the name of plug-in to test
    PLUGIN_NAME = 'base'

    @mock.patch('plugins.base.ViewUpdater', lambda *_: None)
    def setup_plugin(self):
        """
        This function must be overwritten by the test instance.
        In most cases it is sufficient to copy this function.
        """
        return ComparePlugin()

    def test_compare_missing_dep(self):
        self.c_plugin.DEPENDENCIES = ['test_ana']
        self.fw_one.processed_analysis['test_ana'] = {}
        result = self.c_plugin.compare([self.fw_one, self.fw_two])
        assert result == {
            'Compare Skipped': {'all': 'Required analysis not present: test_ana'}
        }, 'missing dep result not correct'

    def test_compare(self):
        result = self.c_plugin.compare([self.fw_one, self.fw_two])
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

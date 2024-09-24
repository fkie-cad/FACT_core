import pytest

from compare.PluginBase import CompareBasePlugin as ComparePlugin
from test.common_helper import CommonDatabaseMock, create_test_firmware

fw_one = create_test_firmware(device_name='dev_1', all_files_included_set=True)
fw_two = create_test_firmware(device_name='dev_2', bin_path='container/test.7z', all_files_included_set=True)
fw_three = create_test_firmware(device_name='dev_3', bin_path='container/test.cab', all_files_included_set=True)


@pytest.fixture
def compare_plugin():
    return ComparePlugin(view_updater=CommonDatabaseMock())


@pytest.mark.backend_config_overwrite(
    {
        'ssdeep_ignore': 80,
    }
)
class TestPluginBase:
    def test_compare_missing_dep(self, compare_plugin):
        compare_plugin.DEPENDENCIES = ['test_ana']
        fw_one.processed_analysis['test_ana'] = {}
        result = compare_plugin.compare([fw_one, fw_two], {})
        assert result == {
            'Compare Skipped': {'all': 'Required analyses not present: test_ana'}
        }, 'missing dep result not correct'

    def test_compare(self, compare_plugin):
        result = compare_plugin.compare([fw_one, fw_two], {})
        assert result == {'dummy': {'all': 'dummy-content', 'collapse': False}}, 'result not correct'


class MockFileObject:
    def __init__(self, processed_analysis_list):
        self.processed_analysis = processed_analysis_list


@pytest.mark.parametrize(
    ('fo_list', 'dependencies', 'expected_output'),
    [
        ([MockFileObject([])], ['a'], {'a'}),
        ([MockFileObject(['a'])], ['a'], set()),
        ([MockFileObject(['a', 'b'])], ['a', 'b', 'c', 'd'], {'c', 'd'}),
        ([MockFileObject(['b']), MockFileObject(['a'])], ['a', 'b'], {'a', 'b'}),
    ],
)
def test_get_missing_analysis_deps(fo_list, dependencies, expected_output):
    plugin = ComparePlugin()
    plugin.DEPENDENCIES = dependencies
    assert plugin._get_missing_analysis_deps(fo_list) == expected_output


def test_missing_comparison_deps():
    plugin = ComparePlugin()
    plugin.COMPARISON_DEPS = ['a', 'b', 'c']
    dependency_results = {
        'a': {'foo': 'bar'},
        'b': {'Comparison Skipped': {'all': 'Required analyses not present: some_plugin'}},
    }
    comparison_results = plugin.compare([MockFileObject([])], dependency_results)
    assert comparison_results == {'Comparison Skipped': {'all': 'Required comparison results are missing: b, c'}}

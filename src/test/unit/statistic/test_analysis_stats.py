# pylint: disable=wrong-import-order,redefined-outer-name

import pytest

from analysis.PluginBase import AnalysisBasePlugin
from statistic.analysis_stats import get_plugin_stats
from test.common_helper import create_test_firmware


class MockPlugin(AnalysisBasePlugin):
    NAME = 'mock_plugin'
    FILE = __file__
    VERSION = '0.0'
    ANALYSIS_STATS_LIMIT = 5

    def _add_plugin_version_and_timestamp_to_analysis_result(self, _):
        pass


@pytest.fixture
def mock_plugin():
    plugin = MockPlugin()
    yield plugin
    plugin.shutdown()


def test_get_plugin_stats(mock_plugin):
    mock_plugin.analysis_stats[0] = 1.0
    mock_plugin.analysis_stats[1] = 2.0
    mock_plugin.analysis_stats[2] = 3.0
    mock_plugin.analysis_stats_count.value = 3

    result = get_plugin_stats(mock_plugin)
    assert result == {
        'count': '3',
        'max': '3.00',
        'mean': '2.00',
        'median': '2.00',
        'min': '1.00',
        'std_dev': '0.82',
    }


def test_update_duration_stats(mock_plugin):
    mock_plugin.start()
    assert mock_plugin.analysis_stats_count.value == mock_plugin.analysis_stats_index.value == 0
    fw = create_test_firmware()
    for _ in range(4):
        mock_plugin.add_job(fw)
        mock_plugin.out_queue.get(timeout=1)
    assert mock_plugin.analysis_stats_count.value == mock_plugin.analysis_stats_index.value == 4
    mock_plugin.add_job(fw)
    mock_plugin.out_queue.get(timeout=1)
    assert mock_plugin.analysis_stats_count.value == 5
    assert mock_plugin.analysis_stats_index.value == 0, 'index should start at 0 when max count is reached'

    assert get_plugin_stats(mock_plugin) is not None

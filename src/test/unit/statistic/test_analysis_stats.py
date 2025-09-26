from __future__ import annotations

from dataclasses import dataclass

import pytest
from pydantic import BaseModel

from scheduler.analysis import plugin
from statistic.analysis_stats import get_plugin_stats
from test.common_helper import create_test_firmware


@dataclass
class MockMetadata:
    name: str
    dependencies: list[str]


class MockDependency:
    metadata = MockMetadata('dependency', [])

    class Schema(BaseModel):
        a: int
        b: str


@dataclass
class MockPlugin:
    metadata: MockMetadata

    def get_analysis(self, *_, **__):
        return 1


class MockFSOrganizer:
    def generate_path(self, fw):
        return fw.file_path


@pytest.fixture
def mock_runner():
    runner_config = plugin.PluginRunner.Config(process_count=1, timeout=5)
    metadata = MockMetadata(name='test', dependencies=[MockDependency.metadata.name])
    runner = plugin.PluginRunner(
        MockPlugin(metadata),
        runner_config,
        {MockDependency.metadata.name: MockDependency.Schema},
    )
    runner._fsorganizer = MockFSOrganizer()
    yield runner
    runner.shutdown()


def test_get_plugin_stats(mock_runner):
    mock_runner.stats[0] = 1.0
    mock_runner.stats[1] = 2.0
    mock_runner.stats[2] = 3.0
    mock_runner.stats_count.value = 3

    result = get_plugin_stats(mock_runner.stats, mock_runner.stats_count)
    assert result == {
        'count': '3',
        'max': '3.00',
        'mean': '2.00',
        'median': '2.00',
        'min': '1.00',
        'std_dev': '0.82',
    }


@pytest.mark.flaky(reruns=3)  # test occasionally fails on the CI
def test_update_duration_stats(mock_runner):
    plugin.ANALYSIS_STATS_LIMIT = 5
    mock_runner.start()
    assert mock_runner.stats_count.value == mock_runner._stats_idx.value == 0
    fw = create_test_firmware()
    fw.processed_analysis[MockDependency.metadata.name] = {'result': {'a': 1, 'b': '2'}}
    for _ in range(4):
        mock_runner.queue_analysis(fw)
        mock_runner.out_queue.get(timeout=5)
    assert mock_runner.stats_count.value == mock_runner._stats_idx.value == 4
    mock_runner.queue_analysis(fw)
    mock_runner.out_queue.get(timeout=5)
    assert mock_runner.stats_count.value == 5
    assert mock_runner._stats_idx.value == 0, 'index should start at 0 when max count is reached'

    assert get_plugin_stats(mock_runner.stats, mock_runner.stats_count) is not None

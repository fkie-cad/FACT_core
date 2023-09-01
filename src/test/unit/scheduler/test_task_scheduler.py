from __future__ import annotations

import pytest

from objects.firmware import Firmware
from scheduler.task_scheduler import AnalysisTaskScheduler


class TestAnalysisScheduling:
    class PluginMock:
        def __init__(self, dependencies):
            self.DEPENDENCIES = dependencies
            self.VERSION = 1

    def setup_class(self):
        self.analysis_plugins: dict[str, TestAnalysisScheduling.PluginMock] = {}
        self.scheduler = AnalysisTaskScheduler(self.analysis_plugins)
        self.plugin_list = ['no_deps', 'foo', 'bar']

    def _add_plugins(self):
        self.scheduler.plugins = {
            'no_deps': self.PluginMock(dependencies=[]),
            'foo': self.PluginMock(dependencies=['no_deps']),
            'bar': self.PluginMock(dependencies=['no_deps', 'foo']),
        }

    def _add_plugins_with_recursive_dependencies(self):
        self.scheduler.plugins = {
            'p1': self.PluginMock(['p2', 'p3']),
            'p2': self.PluginMock(['p3']),
            'p3': self.PluginMock([]),
            'p4': self.PluginMock(['p5']),
            'p5': self.PluginMock(['p6']),
            'p6': self.PluginMock([]),
        }

    @pytest.mark.parametrize(
        ('input_data', 'expected_output'),
        [
            (set(), set()),
            ({'p1'}, {'p2', 'p3'}),
            ({'p3'}, set()),
            ({'p1', 'p2', 'p3', 'p4'}, {'p5'}),
        ],
    )
    def test_get_cumulative_remaining_dependencies(self, input_data, expected_output):
        self._add_plugins_with_recursive_dependencies()
        result = self.scheduler.get_cumulative_remaining_dependencies(input_data)
        assert result == expected_output

    @pytest.mark.parametrize(
        ('input_data', 'expected_output'),
        [
            ([], set()),
            (['p3'], {'p3'}),
            (['p1'], {'p1', 'p2', 'p3'}),
            (['p4'], {'p4', 'p5', 'p6'}),
        ],
    )
    def test_add_dependencies_recursively(self, input_data, expected_output):
        self._add_plugins_with_recursive_dependencies()
        result = self.scheduler._add_dependencies_recursively(input_data)
        assert set(result) == expected_output

    @pytest.mark.parametrize(
        ('remaining', 'scheduled', 'expected_output'),
        [
            ({}, [], []),
            ({'no_deps', 'foo', 'bar'}, [], ['no_deps']),
            ({'foo', 'bar'}, ['no_deps'], ['foo']),
            ({'bar'}, ['no_deps', 'foo'], ['bar']),
        ],
    )
    def test_get_plugins_with_met_dependencies(self, remaining, scheduled, expected_output):
        self._add_plugins()
        assert self.scheduler._get_plugins_with_met_dependencies(remaining, scheduled) == expected_output

    @pytest.mark.parametrize(
        ('remaining', 'scheduled', 'expected_output'),
        [
            ({'bar'}, ['no_deps', 'foo'], {'bar'}),
            ({'foo', 'bar'}, ['no_deps', 'foo'], {'foo', 'bar'}),
        ],
    )
    def test_get_plugins_with_met_dependencies__completed_analyses(self, remaining, scheduled, expected_output):
        self._add_plugins()
        assert set(self.scheduler._get_plugins_with_met_dependencies(remaining, scheduled)) == expected_output

    def test_reschedule_failed_analysis_task(self):
        task = Firmware(binary='foo')
        error_message = 'There was an exception'
        task.analysis_exception = ('foo', error_message)
        task.scheduled_analysis = ['no_deps', 'bar']
        self._add_plugins()
        self.scheduler.reschedule_failed_analysis_task(task)

        assert 'foo' in task.processed_analysis
        assert task.processed_analysis['foo']['result']['failed'] == error_message
        assert 'bar' not in task.scheduled_analysis
        assert 'bar' in task.processed_analysis
        assert task.processed_analysis['bar']['result']['failed'] == 'Analysis of dependency foo failed'
        assert 'no_deps' in task.scheduled_analysis

    def test_smart_shuffle(self):
        self._add_plugins()
        result = self.scheduler._smart_shuffle(self.plugin_list)
        assert result == ['bar', 'foo', 'no_deps']

    def test_smart_shuffle__impossible_dependency(self):
        self._add_plugins()
        self.scheduler.plugins['impossible'] = self.PluginMock(dependencies=['impossible to meet'])
        result = self.scheduler._smart_shuffle([*self.plugin_list, 'impossible'])
        assert 'impossible' not in result
        assert result == ['bar', 'foo', 'no_deps']

    def test_smart_shuffle__circle_dependency(self):
        self.scheduler.plugins = {
            'p1': self.PluginMock(['p2']),
            'p2': self.PluginMock(['p3']),
            'p3': self.PluginMock(['p1']),
        }
        result = self.scheduler._smart_shuffle(['p1', 'p2', 'p3'])
        assert result == []

from __future__ import annotations

from dataclasses import KW_ONLY, dataclass, field
from multiprocessing import Queue
from time import sleep
from unittest import mock

import pytest
from semver import Version

from objects.firmware import Firmware
from scheduler.analysis import AnalysisScheduler
from scheduler.task_scheduler import MANDATORY_PLUGINS
from test.common_helper import MockFileObject, get_test_data_dir
from test.mock import mock_patch, mock_spy


class ViewUpdaterMock:
    def update_view(self, *_):
        pass


class BackendDbInterface:
    def get_analysis(self, *_):
        pass


@pytest.mark.common_config_overwrite(
    {
        'file_hashes': {
            'hashes': 'md5, sha1, sha256, sha512, ripemd160, whirlpool',
        },
        'printable_strings': {
            'min-length': 6,
        },
    }
)
class TestScheduleInitialAnalysis:
    def test_plugin_registration(self, analysis_scheduler):
        assert 'ExamplePlugin' in analysis_scheduler.analysis_plugins, 'Example Plugin not found'

    @pytest.mark.SchedulerTestConfig(start_processes=False)
    def test_schedule_firmware_init_no_analysis_selected(self, analysis_scheduler):
        analysis_scheduler.process_queue = Queue()
        test_fw = Firmware(binary=b'test')
        analysis_scheduler.start_analysis_of_object(test_fw)
        test_fw = analysis_scheduler.process_queue.get(timeout=5)
        assert len(test_fw.scheduled_analysis) == len(MANDATORY_PLUGINS), 'Mandatory Plugins not selected'
        for item in MANDATORY_PLUGINS:
            assert item in test_fw.scheduled_analysis

    @pytest.mark.SchedulerTestConfig(start_processes=True)
    def test_whole_run_analysis_selected(self, analysis_scheduler, post_analysis_queue):
        test_fw = Firmware(file_path=get_test_data_dir() / 'get_files_test/testfile1')
        test_fw.scheduled_analysis = ['ExamplePlugin']
        analysis_scheduler.start_analysis_of_object(test_fw)
        analysis_results = [post_analysis_queue.get(timeout=10) for _ in range(3)]
        analysis_results = {plugin: result for uid, plugin, result in analysis_results}
        assert len(analysis_results) == 3, 'analysis not done'
        assert set(analysis_results) == {'file_type', 'ExamplePlugin', 'file_hashes'}
        assert analysis_results['ExamplePlugin']['result']['first_byte'] == '74'
        assert analysis_results['ExamplePlugin']['summary'] == ['big-file', 'binary']

    def test_expected_plugins_are_found(self, analysis_scheduler):
        result = analysis_scheduler.get_plugin_dict()

        assert 'file_hashes' in result, 'file hashes plugin not found'
        assert 'file_type' in result, 'file type plugin not found'

    def test_remove_example_plugins(self, analysis_scheduler):
        # Reloading plugins will discard the already started processes
        analysis_scheduler.shutdown()
        analysis_scheduler._load_plugins()
        analysis_scheduler._remove_example_plugins()

        result = analysis_scheduler.get_plugin_dict()

        assert 'dummy_plugin_for_testing_only' not in result, 'dummy plug-in not removed'
        assert 'ExamplePlugin' not in result, 'ExamplePlugin plug-in not removed'

    def test_get_plugin_dict_description(self, analysis_scheduler):
        result = analysis_scheduler.get_plugin_dict()
        assert (
            result['file_type'][0] == analysis_scheduler.analysis_plugins['file_type'].metadata.description
        ), 'description not correct'

    @pytest.mark.backend_config_overwrite(
        {
            'analysis_preset': {
                'default': {
                    'name': 'default',
                    'plugins': ['file_hashes'],
                },
            }
        }
    )
    def test_get_plugin_dict_flags(self, analysis_scheduler):
        result = analysis_scheduler.get_plugin_dict()

        assert result['file_hashes'][1], 'mandatory flag not set'
        assert result['unpacker'][1], 'unpacker plugin not marked as mandatory'

        assert result['file_hashes'][2]['default'], 'default flag not set'
        assert not result['file_type'][2]['default'], 'default flag set but should not'

    def test_get_plugin_dict_version(self, analysis_scheduler):
        result = analysis_scheduler.get_plugin_dict()
        assert (
            result['file_type'][3] == analysis_scheduler.analysis_plugins['file_type'].metadata.version
        ), 'version not correct'
        assert (
            result['file_hashes'][3] == analysis_scheduler.analysis_plugins['file_hashes'].metadata.version
        ), 'version not correct'

    def test_process_next_analysis_unknown_plugin(self, analysis_scheduler):
        test_fw = Firmware(file_path=get_test_data_dir() / 'get_files_test/testfile1')
        test_fw.scheduled_analysis = ['unknown_plugin']

        with mock_spy(analysis_scheduler, '_start_or_skip_analysis') as spy:
            analysis_scheduler._process_next_analysis_task(test_fw)
            assert not spy.was_called(), 'unknown plugin should simply be skipped'

    @pytest.mark.backend_config_overwrite(
        {
            'plugin': {
                'ExamplePlugin': {
                    'name': 'ExamplePlugin',
                    'mime_whitelist': ['foo', 'bar'],
                },
            }
        }
    )
    def test_skip_analysis_because_whitelist(self, analysis_scheduler, post_analysis_queue):
        test_fw = Firmware(file_path=get_test_data_dir() / 'get_files_test/testfile1')
        test_fw.scheduled_analysis = ['file_hashes']
        test_fw.processed_analysis['file_type'] = {'result': {'mime': 'text/plain'}}
        analysis_scheduler._start_or_skip_analysis('ExamplePlugin', test_fw)
        uid, plugin, analysis_result = post_analysis_queue.get(timeout=10)
        assert plugin == 'ExamplePlugin'
        assert 'skipped' in analysis_result['result']


class TestAnalysisSchedulerBlacklist:
    test_plugin = 'test_plugin'
    file_object = MockFileObject()

    class PluginMock:
        def __init__(self, blacklist=None, whitelist=None):
            self.metadata = MetaDataMock()
            if blacklist:
                self.metadata.mime_blacklist = blacklist
            if whitelist:
                self.metadata.mime_whitelist = whitelist

        def shutdown(self):
            pass

    @classmethod
    def setup_class(cls):
        cls.init_patch = mock.patch(  # noqa: PT008
            target='scheduler.analysis.AnalysisScheduler.__init__', new=lambda *_: None
        )
        cls.init_patch.start()
        cls.sched = AnalysisScheduler()
        cls.sched.analysis_plugins = {}
        cls.plugin_list = ['no_deps', 'foo', 'bar']
        cls.init_patch.stop()

    def test_get_blacklist_and_whitelist_from_plugin(self):
        self.sched.analysis_plugins['test_plugin'] = self.PluginMock(['foo'], ['bar'])
        blacklist, whitelist = self.sched._get_blacklist_and_whitelist_from_plugin('test_plugin')
        assert (blacklist, whitelist) == (['foo'], ['bar'])

    def test_get_blacklist_and_whitelist_from_plugin__missing_in_plugin(self):
        self.sched.analysis_plugins['test_plugin'] = self.PluginMock(['foo'])
        blacklist, whitelist = self.sched._get_blacklist_and_whitelist_from_plugin('test_plugin')
        assert whitelist == []
        assert isinstance(blacklist, list)

    @pytest.mark.backend_config_overwrite(
        {
            'plugin': {
                'test_plugin': {
                    'name': 'test_plugin',
                    'mime_blacklist': ['type1', 'type2'],
                }
            }
        }
    )
    def test_get_blacklist_and_whitelist_from_config(self):
        blacklist, whitelist = self.sched._get_blacklist_and_whitelist_from_config('test_plugin')
        assert blacklist == ['type1', 'type2']
        assert whitelist == []

    @pytest.mark.backend_config_overwrite(
        {
            'plugin': {
                'test_plugin': {
                    'name': 'test_plugin',
                    'mime_blacklist': ['type1', 'type2'],
                }
            }
        }
    )
    def test_get_blacklist_and_whitelist__in_config_and_plugin(self):
        self.sched.analysis_plugins['test_plugin'] = self.PluginMock(['foo'], ['bar'])
        blacklist, whitelist = self.sched._get_blacklist_and_whitelist('test_plugin')
        assert blacklist == ['type1', 'type2']
        assert whitelist == []

    def test_get_blacklist_and_whitelist__plugin_only(self):
        self.sched.analysis_plugins['test_plugin'] = self.PluginMock(['foo'], ['bar'])
        blacklist, whitelist = self.sched._get_blacklist_and_whitelist('test_plugin')
        assert (blacklist, whitelist) == (['foo'], ['bar'])

    def test_next_analysis_is_blacklisted__blacklisted(self):
        self.sched.analysis_plugins[self.test_plugin] = self.PluginMock(blacklist=['blacklisted_type'])
        self.file_object.processed_analysis['file_type']['result']['mime'] = 'blacklisted_type'
        blacklisted = self.sched._next_analysis_is_blacklisted(self.test_plugin, self.file_object)
        assert blacklisted is True

    def test_next_analysis_is_blacklisted__not_blacklisted(self):
        self.sched.analysis_plugins[self.test_plugin] = self.PluginMock(blacklist=[])
        self.file_object.processed_analysis['file_type']['result']['mime'] = 'not_blacklisted_type'
        blacklisted = self.sched._next_analysis_is_blacklisted(self.test_plugin, self.file_object)
        assert blacklisted is False

    def test_next_analysis_is_blacklisted__whitelisted(self):
        self.sched.analysis_plugins[self.test_plugin] = self.PluginMock(whitelist=['whitelisted_type'])
        self.file_object.processed_analysis['file_type']['result']['mime'] = 'whitelisted_type'
        blacklisted = self.sched._next_analysis_is_blacklisted(self.test_plugin, self.file_object)
        assert blacklisted is False

    def test_next_analysis_is_blacklisted__not_whitelisted(self):
        self.sched.analysis_plugins[self.test_plugin] = self.PluginMock(whitelist=['some_other_type'])
        self.file_object.processed_analysis['file_type']['result']['mime'] = 'not_whitelisted_type'
        blacklisted = self.sched._next_analysis_is_blacklisted(self.test_plugin, self.file_object)
        assert blacklisted is True

    def test_next_analysis_is_blacklisted__whitelist_precedes_blacklist(self):
        self.sched.analysis_plugins[self.test_plugin] = self.PluginMock(
            blacklist=['test_type'], whitelist=['test_type']
        )
        self.file_object.processed_analysis['file_type']['result']['mime'] = 'test_type'
        blacklisted = self.sched._next_analysis_is_blacklisted(self.test_plugin, self.file_object)
        assert blacklisted is False

        self.sched.analysis_plugins[self.test_plugin] = self.PluginMock(blacklist=[], whitelist=['some_other_type'])
        self.file_object.processed_analysis['file_type']['result']['mime'] = 'test_type'
        blacklisted = self.sched._next_analysis_is_blacklisted(self.test_plugin, self.file_object)
        assert blacklisted is True

    def test_get_blacklist_file_type_from_database(self):
        def add_file_type_mock(_, fo):
            fo.processed_analysis['file_type'] = {'result': {'mime': 'foo_type'}}

        file_object = MockFileObject()
        file_object.processed_analysis.pop('file_type')
        with mock_patch(self.sched, '_add_completed_analysis_results_to_file_object', add_file_type_mock):
            result = self.sched._get_file_type_from_object_or_db(file_object)
            assert result == 'foo_type'


class TestAnalysisSkipping:
    class PluginMock:
        def __init__(self, version, system_version):
            self.metadata = MetaDataMock(version=version, name='test plug-in')
            if system_version:
                self.metadata.system_version = system_version

    class BackendMock:
        def __init__(self, analysis_result):
            self.analysis_entry = analysis_result

        def get_analysis(self, *_):
            return self.analysis_entry

    @classmethod
    def setup_class(cls):
        cls.init_patch = mock.patch(  # noqa: PT008
            target='scheduler.analysis.AnalysisScheduler.__init__', new=lambda *_: None
        )
        cls.init_patch.start()

        cls.scheduler = AnalysisScheduler()
        cls.scheduler.analysis_plugins = {}

        cls.init_patch.stop()

    @pytest.mark.parametrize(
        (
            'plugin_version',
            'plugin_system_version',
            'analysis_plugin_version',
            'analysis_system_version',
            'expected_output',
        ),
        [
            (Version(1, 0), None, '1.0.0', None, True),
            (Version(1, 1), None, '1.0.0', None, False),
            (Version(1, 0), None, '1.1.0', None, True),
            (Version(1, 0), '2.0', '1.0.0', '2.0', True),
            (Version(1, 0), '2.0', '1.0.0', '2.1', True),
            (Version(1, 0), '2.1', '1.0.0', '2.0', False),
            (Version(1, 0), '2.0', '1.0.0', None, False),
            ('foo', '1.1', '1.1.0', '1.0', False),  # invalid version string
        ],
    )
    def test_analysis_is_already_in_db_and_up_to_date(
        self, plugin_version, plugin_system_version, analysis_plugin_version, analysis_system_version, expected_output
    ):
        plugin = 'foo'
        analysis_entry = {
            'plugin': plugin,
            'plugin_version': analysis_plugin_version,
            'system_version': analysis_system_version,
            'result': {},
        }
        self.scheduler.db_backend_service = self.BackendMock(analysis_entry)
        self.scheduler.analysis_plugins[plugin] = self.PluginMock(
            version=plugin_version, system_version=plugin_system_version
        )
        assert self.scheduler._analysis_is_already_in_db_and_up_to_date(plugin, '') == expected_output

    @pytest.mark.parametrize(
        'db_entry',
        [
            {
                'plugin': 'plugin',
                'plugin_version': '1.0',
                'result': {},
            },  # 'system_version' missing
            {
                'plugin': 'plugin',
                'result': {'failed': 'reason'},
                'plugin_version': '1.0',
                'system_version': '1.0',
            },  # failed
        ],
    )
    def test_analysis_is_already_in_db_and_up_to_date__incomplete(self, db_entry):
        self.scheduler.db_backend_service = self.BackendMock(db_entry)
        self.scheduler.analysis_plugins['plugin'] = self.PluginMock(version='1.0', system_version='1.0')
        assert self.scheduler._analysis_is_already_in_db_and_up_to_date('plugin', '') is False

    def test_is_forced_update(self):
        fo = MockFileObject()
        assert self.scheduler._is_forced_update(fo) is False
        fo.force_update = False
        assert self.scheduler._is_forced_update(fo) is False
        fo.force_update = True
        assert self.scheduler._is_forced_update(fo) is True


class TestAnalysisShouldReanalyse:
    class PluginMock:
        def __init__(self, plugin_version, system_version):
            self.metadata = MetaDataMock(version=plugin_version, system_version=system_version)
            self.metadata.dependencies = ['plugin_dep']
            self.metadata.name = 'plugin_root'

    class BackendMock:
        def __init__(self, dependency_analysis_date, system_version=None):
            self.date = dependency_analysis_date
            self.system_version = system_version

        def get_analysis(self, *_):
            return {'analysis_date': self.date, 'system_version': None}

    @classmethod
    def setup_class(cls):
        cls.init_patch = mock.patch(  # noqa: PT008
            target='scheduler.analysis.AnalysisScheduler.__init__', new=lambda *_: None
        )
        cls.init_patch.start()
        cls.scheduler = AnalysisScheduler()
        cls.init_patch.stop()

    @pytest.mark.parametrize(
        (
            'plugin_date',
            'dependency_date',
            'plugin_version',
            'system_version',
            'db_plugin_version',
            'db_system_version',
            'expected_result',
        ),
        [
            (10, 20, Version(1, 0), None, '1.0.0', None, False),  # analysis date < dependency date => not up to date
            (20, 10, Version(1, 0), None, '1.0.0', None, True),  # analysis date > dependency date => up to date
            (20, 10, Version(1, 1), None, '1.0.0', None, False),  # plugin version > db version => not up to date
            (20, 10, Version(1, 0), None, '1.1.0', None, True),  # plugin version < db version => up to date
            (20, 10, Version(1, 0), '1.1', '1.0.0', '1.0', False),  # system version > db sys version => not up to date
            (20, 10, Version(1, 0), '1.0', '1.0.0', '1.1', True),  # system version < db sys version => up to date
            (20, 10, Version(1, 0), '1.0', '1.0.0', None, False),  # system version didn't exist in db => not up to date
            (20, 10, 'foo', '1.0', '1.0', None, False),  # invalid version => not up to date
        ],
    )
    def test_analysis_is_up_to_date(  # noqa: PLR0913
        self,
        plugin_date,
        dependency_date,
        plugin_version,
        system_version,
        db_plugin_version,
        db_system_version,
        expected_result,
    ):
        analysis_db_entry = {
            'plugin_version': db_plugin_version,
            'analysis_date': plugin_date,
            'system_version': db_system_version,
        }
        self.scheduler.db_backend_service = self.BackendMock(dependency_date)
        plugin = self.PluginMock(plugin_version, system_version)
        assert self.scheduler._analysis_is_up_to_date(analysis_db_entry, plugin, 'uid') == expected_result


@dataclass
class MetaDataMock:
    _: KW_ONLY
    name: str = 'mock_plugin'
    dependencies: list[str] = field(default_factory=list)
    version: Version = field(default=Version(0, 1, 0))
    system_version: str | None = None


class MockRunner:
    def __init__(self):
        self._in_queue = Queue()

    def get_queue_len(self):
        return self._in_queue.qsize()


def test_combined_analysis_workload(monkeypatch):
    monkeypatch.setattr(AnalysisScheduler, '__init__', lambda *_: None)
    scheduler = AnalysisScheduler()

    scheduler.analysis_plugins = {}
    scheduler._plugin_runners = {}
    dummy_runner = scheduler._plugin_runners['dummy_plugin'] = MockRunner()
    scheduler.process_queue = Queue()
    try:
        assert scheduler.get_combined_analysis_workload() == 0
        scheduler.process_queue.put({})
        for _ in range(2):
            dummy_runner._in_queue.put({})
        assert scheduler.get_combined_analysis_workload() == 3
    finally:
        sleep(0.1)  # let the queue finish internally to not cause "Broken pipe"
        scheduler.process_queue.close()
        dummy_runner._in_queue.close()

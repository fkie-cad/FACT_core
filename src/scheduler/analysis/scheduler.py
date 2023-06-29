from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Lock, Queue, Value
from queue import Empty
from time import sleep

from packaging.version import InvalidVersion
from packaging.version import parse as parse_version

import config
from analysis.PluginBase import AnalysisBasePlugin
from analysis.plugin import AnalysisPluginV0
from helperFunctions.compare_sets import substring_is_in_list
from helperFunctions.logging import TerminalColors, color_string
from helperFunctions.plugin import discover_analysis_plugins
from helperFunctions.process import ExceptionSafeProcess, check_worker_exceptions, stop_processes
from objects.file import FileObject
from scheduler.analysis_status import AnalysisStatus
from scheduler.task_scheduler import MANDATORY_PLUGINS, AnalysisTaskScheduler
from statistic.analysis_stats import get_plugin_stats
from storage.db_interface_backend import BackendDbInterface
from storage.db_interface_base import DbInterfaceError
from storage.fsorganizer import FSOrganizer
from storage.unpacking_locks import UnpackingLockManager
from pathlib import Path

from .plugin import PluginRunner, Worker
from storage.db_interface_view_sync import ViewUpdater


class AnalysisScheduler:  # pylint: disable=too-many-instance-attributes
    '''
    The analysis scheduler is responsible for

    * initializing analysis plugins
    * scheduling tasks based on user decision and built-in dependencies
    * deciding if tasks should run or may be skipped
    * running the tasks
    * and storing the new results of analysis tasks in the database

    Plugin initialization is mostly handled by the plugins, the scheduler only provides an attachment point and offers
    a single point of reference for introspection and runtime information.

    The scheduler offers three entry points:

    #. Start the analysis of a file object (start_analysis_of_object)
    #. Start the analysis of a file object without context (update_analysis_of_single_object)
    #. Start an update of a firmware file and all it's children (update_analysis_of_object_and_children)

    Entry point 1. is used by the unpacking scheduler and is trigger for each file object after the unpacking has been
    processed. Entry points 2. and 3. are independent of the unpacking process and can be triggered by the user using
    the Web-UI or REST-API. 2. is used to update analyses for a single file. 3. is used to update analyses for all files
    contained inside a given firmware. The difference between 1. and 2. is that the single file update (2.) will not be
    considered in the current analysis introspection.

    Scheduling of tasks is made with the following considerations:

    * New objects need a set of mandatory plugins (e.g. file type and hashes), as these results are used in further
      processing stages
    * Plugins can have dependencies, these have to be present before the depending plugin can be run
    * The order of execution is shuffled (dependency preserving) to balance execution of the plugins

    After scheduling, for each task a set of checks is run to decide if a task might be skipped: class::

        ┌─┬──────────────┐ No                                   ┌────────┐
        │0│Plugin exists?├──────────────────────────────────────►        │
        └─┴───┬──────────┘                                      │  Skip  │
              │ Yes                                     ┌───────►        ◄───┐
        ┌─┬───▼─────────────┐ Yes                       │       └────────┘   │
        │1│Is forced update?├───────────────────────────┼─────┐              │
        └─┴───┬─────────────┘                           │     │              │
              │ No                                      │     │              │
        ┌─┬───▼────────────────────────────────┐ Yes    │     │              │
        │2│Analysis present, version unchanged?├────────┘     │              │
        └─┴───┬────────────────────────────────┘              │ ┌─────────┐  │
              │ No                                            └─►         │  │
        ┌─┬───▼────────────────────────────┐ No                 │  Start  │  │
        │3│Analysis is black / whitelisted?├────────────────────►         │  │
        └─┴───┬────────────────────────────┘                    └─────────┘  │
              │ Yes                                                          │
              └──────────────────────────────────────────────────────────────┘

    Running the analysis tasks is achieved through (multiprocessing.Queue)s. Each plugin has an in-queue, triggered
    by the scheduler using the `add_job` function, and an out-queue that is processed by the result collector. The
    actual analysis process is out of scope. Database interaction happens before (pre_analysis) and after
    (post_analysis) the running of a task, to store intermediate results for live updates, and final results.

    :param pre_analysis: A database callback to execute before running an analysis task.
    :param post_analysis: A database callback to execute after running an analysis task.
    :param db_interface: An object reference to an instance of BackEndDbInterface.
    :param unpacking_locks: An instance of UnpackingLockManager.
    '''

    def __init__(
        self,
        pre_analysis: Callable[[FileObject], None] = None,
        post_analysis: Callable[[str, str, dict], None] = None,
        db_interface=None,
        unpacking_locks: UnpackingLockManager | None = None,
    ):
        self.analysis_plugins = {}
        self._plugin_runners = {}

        self._load_plugins()
        self.stop_condition = Value('i', 0)
        self.process_queue = Queue()
        self.unpacking_locks = unpacking_locks
        self.scheduling_lock = Lock()

        self.status = AnalysisStatus()
        self.task_scheduler = AnalysisTaskScheduler(self.analysis_plugins)
        self.schedule_processes = []
        self.result_collector_processes = []

        self.fs_organizer = FSOrganizer()
        self.db_backend_service = db_interface if db_interface else BackendDbInterface()
        self.pre_analysis = pre_analysis if pre_analysis else self.db_backend_service.add_object
        self.post_analysis = post_analysis if post_analysis else self.db_backend_service.add_analysis

    def start(self):
        self._start_runner_processes()
        self._start_result_collector()
        self._start_plugins()
        logging.info('Analysis System online...')
        logging.info(f'Plugins available: {self._get_list_of_available_plugins()}')

    def shutdown(self):
        '''
        Shutdown the runner process, the result collector and all plugin processes. A multiprocessing.Value is set to
        notify all attached processes of the impending shutdown. Afterwards queues are closed once it's safe.
        '''
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        futures = []
        # first shut down scheduling, then analysis plugins and lastly the result collector
        stop_processes(self.schedule_processes, config.backend.block_delay + 1)

        for runner in self._plugin_runners.values():
            runner.shutdown()

        for runner in self._plugin_runners.values():
            for worker in runner._workers:
                if not worker.is_alive():
                    continue
                worker.join(Worker.SIGTERM_TIMEOUT + 1)

        with ThreadPoolExecutor() as pool:
            for plugin in self.analysis_plugins.values():
                futures.append(pool.submit(plugin.shutdown))
            for future in futures:
                future.result()  # call result to make sure all threads are finished and there are no exceptions
        stop_processes(self.result_collector_processes, config.backend.block_delay + 1)
        self.process_queue.close()
        self.status.shutdown()
        logging.info('Analysis System offline')

    def update_analysis_of_object_and_children(self, fo: FileObject):
        '''
        This function is used to analyze an object and all its recursively included objects without repeating the
        extraction process. Scheduled analyses are propagated to the included objects.

        :param fo: The root file that is to be analyzed
        '''
        included_files = self.db_backend_service.get_list_of_all_included_files(fo)
        self.pre_analysis(fo)
        self.unpacking_locks.release_unpacking_lock(fo.uid)
        self.status.add_update_to_current_analyses(fo, included_files)
        for child_fo in self.db_backend_service.get_objects_by_uid_list(included_files):
            child_fo.root_uid = fo.uid  # set correct root_uid so that "current analysis stats" work correctly
            child_fo.force_update = getattr(fo, 'force_update', False)  # propagate forced update to children
            self.task_scheduler.schedule_analysis_tasks(child_fo, fo.scheduled_analysis)
            self._check_further_process_or_complete(child_fo)
        self._check_further_process_or_complete(fo)

    def start_analysis_of_object(self, fo: FileObject):
        '''
        This function is used to start analysis of a firmware object. The function registers the firmware with the
        status module such that the progress of the firmware and its included files is tracked.

        :param fo: The firmware that is to be analyzed
        '''
        # FixMe: remove this when no duplicate files come from unpacking any more
        with self.scheduling_lock:  # if multiple unpacking threads call this in parallel, this can cause DB errors
            try:
                self.pre_analysis(fo)
            except DbInterfaceError as error:
                # trying to add an object to the DB could lead to an error if the root FW or the parents are missing
                # (e.g. because they were recently deleted)
                logging.error(f'Could not add {fo.uid} to the DB: {error}')
                return

        if self.status.file_should_be_analyzed(fo):
            self.status.add_to_current_analyses(fo)
            self.task_scheduler.schedule_analysis_tasks(fo, fo.scheduled_analysis, mandatory=True)
            self._check_further_process_or_complete(fo)
        else:
            logging.info(f'Skipping analysis of {fo.uid} (duplicate file)')

    def update_analysis_of_single_object(self, fo: FileObject):
        '''
        This function is used to add analysis tasks for a single file. This function has no side effects so the object
        is simply iterated until all scheduled analyses are processed or skipped.

        :param fo: The file that is to be analyzed
        '''
        self.task_scheduler.schedule_analysis_tasks(fo, fo.scheduled_analysis)
        self._check_further_process_or_complete(fo)

    def _get_list_of_available_plugins(self) -> list[str]:
        return sorted(self.analysis_plugins, key=str.lower)

    # ---- plugin initialization ----

    def _remove_example_plugins(self):
        plugins = ['dummy_plugin_for_testing_only', 'ExamplePlugin']
        for plugin in plugins:
            self._plugin_runners.pop(plugin, None)
            self.analysis_plugins.pop(plugin, None)

    def _load_plugins(self):
        schemata = {}

        for plugin_module in discover_analysis_plugins():
            try:
                # pylint:disable=invalid-name
                PluginClass = plugin_module.AnalysisPlugin
                if issubclass(PluginClass, AnalysisPluginV0):
                    plugin: AnalysisPluginV0 = PluginClass()
                    self.analysis_plugins[plugin.metadata.name] = plugin
                    schemata[plugin.metadata.name] = PluginClass.Schema
                    _sync_view(plugin_module, plugin.metadata.name)
                elif issubclass(PluginClass, AnalysisBasePlugin):
                    self.analysis_plugins[PluginClass.NAME] = PluginClass()
                    schemata[PluginClass.NAME] = dict
            except Exception:  # pylint: disable=broad-except
                logging.error(f'Could not import analysis plugin {plugin_module.AnalysisPlugin.NAME}', exc_info=True)

        for plugin in self.analysis_plugins.values():
            if not isinstance(plugin, AnalysisPluginV0):
                continue

            try:
                process_count = getattr(config.backend.plugin[plugin], 'processes')
            except (AttributeError, KeyError):
                process_count = config.backend.plugin_defaults.processes

            runner_config = PluginRunner.Config(
                process_count=process_count,
                timeout=plugin.metadata.timeout,
            )
            runner = PluginRunner(plugin, runner_config, schemata)
            self._plugin_runners[plugin.metadata.name] = runner

        # FIXME: This is a hack and should be remove once we have unified fixtures for the scheduler
        if not os.getenv('PYTEST_CURRENT_TEST'):
            self._remove_example_plugins()

    def get_plugin_dict(self) -> dict:
        '''
        Get information regarding all loaded plugins in form of a dictionary with the following form:

        .. code-block:: python

            {
                NAME: (
                    str: DESCRIPTION,
                    bool: mandatory,
                    dict: plugin_sets,
                    str: VERSION,
                    list: DEPENDENCIES,
                    list: MIME_BLACKLIST,
                    list: MIME_WHITELIST,
                    str: config.threads
                )
            }

        Mandatory plugins are not shown in the analysis selection but always executed. Default plugins are pre-selected
        in the analysis selection.

        :return: dict with information regarding all loaded plugins
        '''
        plugin_list = self._get_list_of_available_plugins()
        plugin_sets = config.backend.analysis_preset
        result = {}
        for plugin in plugin_list:
            current_plugin_plugin_sets = {}
            mandatory_flag = plugin in MANDATORY_PLUGINS
            for plugin_set in plugin_sets:
                current_plugin_plugin_sets[plugin_set] = plugin in plugin_sets[plugin_set].plugins
            blacklist, whitelist = self._get_blacklist_and_whitelist_from_plugin(plugin)
            try:
                thread_count = getattr(config.backend.plugin[plugin], 'processes')
            except (AttributeError, KeyError):
                thread_count = config.backend.plugin_defaults.processes
            # TODO this should not be a tuple but rather a dictionary/class
            result[plugin] = (
                self.analysis_plugins[plugin].DESCRIPTION,
                mandatory_flag,
                dict(current_plugin_plugin_sets),
                self.analysis_plugins[plugin].VERSION,
                self.analysis_plugins[plugin].DEPENDENCIES,
                blacklist,
                whitelist,
                thread_count,
            )
        result['unpacker'] = ('Additional information provided by the unpacker', True, False)
        return result

    def _start_plugins(self):
        for plugin in self.analysis_plugins.values():
            plugin.start()

        for runner in self._plugin_runners.values():
            runner.start()

    # ---- task runner functions ----

    def _start_runner_processes(self):
        self.schedule_processes = [
            ExceptionSafeProcess(target=self._task_runner) for _ in range(config.backend.scheduling_worker_count)
        ]
        for process in self.schedule_processes:
            process.start()

    def _task_runner(self):
        logging.debug(f'Started analysis scheduler (pid={os.getpid()})')
        while self.stop_condition.value == 0:
            try:
                task = self.process_queue.get(timeout=config.backend.block_delay)
            except Empty:
                pass
            else:
                self._process_next_analysis_task(task)

    def _process_next_analysis_task(self, fw_object: FileObject):
        self.unpacking_locks.release_unpacking_lock(fw_object.uid)
        analysis_to_do = fw_object.scheduled_analysis.pop()
        if analysis_to_do not in self.analysis_plugins:
            logging.error(f'Plugin \'{analysis_to_do}\' not available')
            self._check_further_process_or_complete(fw_object)
        else:
            self._start_or_skip_analysis(analysis_to_do, fw_object)

    def _start_or_skip_analysis(self, analysis_to_do: str, file_object: FileObject):
        if not self._is_forced_update(file_object) and self._analysis_is_already_in_db_and_up_to_date(
            analysis_to_do, file_object.uid
        ):
            logging.debug(f'skipping analysis "{analysis_to_do}" for {file_object.uid} (analysis already in DB)')
            if analysis_to_do in self.task_scheduler.get_cumulative_remaining_dependencies(
                file_object.scheduled_analysis
            ):
                self._add_completed_analysis_results_to_file_object(analysis_to_do, file_object)
            self.status.update_post_analysis(file_object, analysis_to_do)
            self._check_further_process_or_complete(file_object)
        elif analysis_to_do not in MANDATORY_PLUGINS and self._next_analysis_is_blacklisted(
            analysis_to_do, file_object
        ):
            logging.debug(f'skipping analysis "{analysis_to_do}" for {file_object.uid} (blacklisted file type)')
            analysis_result = self._get_skipped_analysis_result(analysis_to_do)
            file_object.processed_analysis[analysis_to_do] = analysis_result
            self.status.update_post_analysis(file_object, analysis_to_do)
            self.post_analysis(file_object.uid, analysis_to_do, analysis_result)
            self._check_further_process_or_complete(file_object)
        else:
            if file_object.binary is None:
                self._set_binary(file_object)
            plugin = self.analysis_plugins[analysis_to_do]
            if isinstance(plugin, AnalysisPluginV0):
                runner = self._plugin_runners[plugin.metadata.name]

                if _dependencies_are_unfulfilled(plugin, file_object):
                    logging.error(f'{file_object.uid}: dependencies of plugin {plugin.metadata.name} not fulfilled')
                    return

                runner.queue_analysis(file_object)
            elif isinstance(plugin, AnalysisBasePlugin):
                plugin.add_job(file_object)

    def _set_binary(self, file_object: FileObject):
        # the file_object.binary may be missing in case of an update
        if file_object.file_path is None:
            file_object.file_path = self.fs_organizer.generate_path(file_object)
        file_object.create_binary_from_path()

    # ---- 1. Is forced update ----

    @staticmethod
    def _is_forced_update(file_object: FileObject) -> bool:
        try:
            return bool(getattr(file_object, 'force_update', False))
        except AttributeError:
            return False

    # ---- 2. Analysis present and plugin version unchanged ----

    def _analysis_is_already_in_db_and_up_to_date(self, analysis_to_do: str, uid: str) -> bool:
        db_entry = self.db_backend_service.get_analysis(uid, analysis_to_do)
        if db_entry is None or 'failed' in db_entry:
            return False
        if db_entry['plugin_version'] is None:
            logging.error(f'Plugin Version missing: UID: {uid}, Plugin: {analysis_to_do}')
            return False
        return self._analysis_is_up_to_date(db_entry, self.analysis_plugins[analysis_to_do], uid)

    def _analysis_is_up_to_date(self, db_entry: dict, analysis_plugin: AnalysisBasePlugin, uid: str) -> bool:
        try:
            current_system_version = analysis_plugin.SYSTEM_VERSION
        except AttributeError:
            current_system_version = None

        try:
            if self._current_version_is_newer(analysis_plugin.VERSION, current_system_version, db_entry):
                return False
        except TypeError:
            logging.error(f'plug-in or system version of "{analysis_plugin.NAME}" plug-in is or was invalid!')
            return False
        except InvalidVersion as error:
            logging.exception(f'Error while parsing plugin version: {error}')
            return False

        return self._dependencies_are_up_to_date(db_entry, analysis_plugin, uid)

    @staticmethod
    def _current_version_is_newer(
        current_plugin_version: str, current_system_version: str | None, db_entry: dict[str, str | None]
    ) -> bool:
        plugin_version_is_newer = parse_version(current_plugin_version) > parse_version(db_entry['plugin_version'])
        system_version_is_newer = parse_version(_fix_system_version(current_system_version)) > parse_version(
            _fix_system_version(db_entry.get('system_version'))
        )
        return plugin_version_is_newer or system_version_is_newer

    def _dependencies_are_up_to_date(self, db_entry: dict, analysis_plugin: AnalysisBasePlugin, uid: str) -> bool:
        for dependency in analysis_plugin.DEPENDENCIES:
            dependency_entry = self.db_backend_service.get_analysis(uid, dependency)
            if db_entry['analysis_date'] < dependency_entry['analysis_date']:
                return False
        return True

    def _add_completed_analysis_results_to_file_object(self, analysis_to_do: str, fw_object: FileObject):
        db_entry = self.db_backend_service.get_analysis(fw_object.uid, analysis_to_do)
        fw_object.processed_analysis[analysis_to_do] = db_entry

    # ---- 3. blacklist and whitelist ----

    def _get_skipped_analysis_result(self, analysis_to_do: str) -> dict:
        return {
            'summary': [],
            'analysis_date': time.time(),
            'plugin_version': self.analysis_plugins[analysis_to_do].VERSION,
            'result': {
                'skipped': 'blacklisted file type',
            },
        }

    def _next_analysis_is_blacklisted(self, next_analysis: str, fw_object: FileObject):
        blacklist, whitelist = self._get_blacklist_and_whitelist(next_analysis)
        if not (blacklist or whitelist):
            return False
        if blacklist and whitelist:
            message = color_string(f'Configuration of plugin "{next_analysis}" erroneous', TerminalColors.FAIL)
            logging.error(f'{message}: found blacklist and whitelist. Ignoring blacklist.')

        file_type = self._get_file_type_from_object_or_db(fw_object)

        if whitelist:
            return not substring_is_in_list(file_type, whitelist)
        return substring_is_in_list(file_type, blacklist)

    def _get_file_type_from_object_or_db(self, fw_object: FileObject) -> str | None:
        if 'file_type' not in fw_object.processed_analysis:
            self._add_completed_analysis_results_to_file_object('file_type', fw_object)
        return fw_object.processed_analysis['file_type']['result']['mime'].lower()

    def _get_blacklist_and_whitelist(self, next_analysis: str) -> tuple[list, list]:
        blacklist, whitelist = self._get_blacklist_and_whitelist_from_config(next_analysis)
        if not (blacklist or whitelist):
            blacklist, whitelist = self._get_blacklist_and_whitelist_from_plugin(next_analysis)
        return blacklist, whitelist

    @staticmethod
    def _get_blacklist_and_whitelist_from_config(analysis_plugin: str) -> tuple[list, list]:
        blacklist = getattr(config.backend.plugin.get(analysis_plugin, None), 'mime_blacklist', [])
        whitelist = getattr(config.backend.plugin.get(analysis_plugin, None), 'mime_whitelist', [])
        return blacklist, whitelist

    def _get_blacklist_and_whitelist_from_plugin(self, analysis_plugin: str) -> tuple[list, list]:
        try:
            blacklist = self.analysis_plugins[analysis_plugin].MIME_BLACKLIST
        except AttributeError:
            blacklist = []

        try:
            whitelist = self.analysis_plugins[analysis_plugin].MIME_WHITELIST
        except AttributeError:
            whitelist = []

        return blacklist, whitelist

    # ---- result collector functions ----

    def _start_result_collector(self):
        self.result_collector_processes = [
            ExceptionSafeProcess(target=self._result_collector) for _ in range(config.backend.collector_worker_count)
        ]
        for process in self.result_collector_processes:
            process.start()

    def _result_collector(self):
        # Collects the results form plugins and writes them in FileObject.processed_analysis
        logging.debug(f'Started analysis result collector (pid={os.getpid()})')
        while self.stop_condition.value == 0:
            nop = True
            for plugin_name, plugin in self.analysis_plugins.items():
                if isinstance(plugin, AnalysisPluginV0):
                    runner = self._plugin_runners[plugin.metadata.name]
                    out_queue = runner.out_queue
                elif isinstance(plugin, AnalysisBasePlugin):
                    out_queue = plugin.out_queue

                try:
                    if isinstance(plugin, AnalysisPluginV0):
                        fw, entry = out_queue.get_nowait()
                        runner.write_result_in_file_object(entry, fw)
                    elif isinstance(plugin, AnalysisBasePlugin):
                        fw = out_queue.get_nowait()
                except (Empty, ValueError):
                    pass
                else:
                    nop = False
                    self._handle_collected_result(fw, plugin_name)
            if nop:
                sleep(config.backend.block_delay)

    def _handle_collected_result(self, fo: FileObject, plugin_name: str):
        if plugin_name in fo.processed_analysis:
            if fo.analysis_exception:
                self.task_scheduler.reschedule_failed_analysis_task(fo)
            self.status.update_post_analysis(fo, plugin_name)
            self.post_analysis(fo.uid, plugin_name, fo.processed_analysis[plugin_name])
        self._check_further_process_or_complete(fo)

    def _check_further_process_or_complete(self, fw_object):
        if not fw_object.scheduled_analysis:
            logging.info(f'Analysis Completed:\n{fw_object}')
            self.status.remove_from_current_analyses(fw_object)
        else:
            self.process_queue.put(fw_object)

    # ---- miscellaneous functions ----

    def get_combined_analysis_workload(self):
        plugin_queues = [
            plugin.in_queue for plugin in self.analysis_plugins.values() if isinstance(plugin, AnalysisBasePlugin)
        ]
        runner_queue_sum = sum([runner.get_queue_len() for runner in self._plugin_runners.values()])
        return self.process_queue.qsize() + sum(queue.qsize() for queue in plugin_queues) + runner_queue_sum

    def get_scheduled_workload(self) -> dict:
        '''
        Get the current workload of this scheduler. The workload is represented through
        - the general in-queue,
        - the currently running analyses in each plugin and the plugin in-queues,
        - the progress for each currently analyzed firmware and
        - recently finished analyses.

         The result has the form:

         .. code-block:: python

            {
                'analysis_main_scheduler': int(),
                'plugins': dict(),
                'current_analyses': dict(),
                'recently_finished_analyses': dict(),
            }

        :return: Dictionary containing current workload statistics
        '''
        self.status.clear_recently_finished()
        workload = {
            'analysis_main_scheduler': self.process_queue.qsize(),
            'plugins': {},
            'current_analyses': self.status.get_current_analyses_stats(),
            'recently_finished_analyses': dict(self.status.recently_finished),
        }
        for plugin_name, plugin in self.analysis_plugins.items():
            if isinstance(plugin, AnalysisPluginV0):
                runner = self._plugin_runners[plugin_name]
                workload['plugins'][plugin_name] = {
                    'queue': runner.get_queue_len(),
                    'out_queue': runner.out_queue.qsize(),
                    'active': runner.get_active_worker_count(),
                    'stats': get_plugin_stats(runner.stats, runner.stats_count),
                }
            elif isinstance(plugin, AnalysisBasePlugin):
                workload['plugins'][plugin_name] = {
                    'queue': plugin.in_queue.qsize(),
                    'out_queue': plugin.out_queue.qsize(),
                    'active': (sum(plugin.active[i].value for i in range(plugin.thread_count))),
                    'stats': get_plugin_stats(plugin.analysis_stats, plugin.analysis_stats_count),
                }
        return workload

    def check_exceptions(self) -> bool:
        '''
        Iterate all attached processes and see if an exception occurred in any. Depending on configuration, plugin
        exceptions are not registered as they are restarted after an exception occurs.

        :return: Boolean value stating if any attached process ran into an exception
        '''
        for _, plugin in self.analysis_plugins.items():
            if isinstance(plugin, AnalysisPluginV0):
                continue
            if plugin.check_exceptions():
                return True
        return check_worker_exceptions(self.schedule_processes + self.result_collector_processes, 'Scheduler')


def _fix_system_version(system_version: str | None) -> str:
    # the system version is optional -> return '0' if it is '' or None
    # YARA plugins used an invalid system version x.y_z (may still be in DB) -> replace all underscores with dashes
    return system_version.replace('_', '-') if system_version else '0'


def _dependencies_are_unfulfilled(plugin: AnalysisPluginV0, fw_object: FileObject):
    # FIXME plugins can be in processed_analysis and could still be skipped, etc. -> need a way to verify that
    # FIXME the analysis ran successfully
    return any(dep not in fw_object.processed_analysis for dep in plugin.metadata.dependencies)


def _sync_view(plugin_module, plugin_name):
    view_path = _get_view_path(plugin_module, plugin_name)

    if view_path is None:
        return

    _view_updater = ViewUpdater()

    _view_updater.update_view(
        plugin_name,
        view_path.read_bytes(),
    )


def _get_view_path(plugin_module, plugin_name) -> Path | None:
    views_dir = Path(plugin_module.__file__).parent.parent / 'view'
    view_files = list(views_dir.iterdir()) if views_dir.is_dir() else []

    if len(view_files) == 0:
        logging.debug(f'{plugin_name}: No view available! Generic view will be used.')
        return None

    if len(view_files) > 1:
        raise RuntimeError(f'{plugin_name}: Plug-in provides more than one view!')

    assert len(view_files) == 1
    return view_files[0]

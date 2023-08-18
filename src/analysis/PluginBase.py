# noqa: N999
from __future__ import annotations

import logging
import os
from multiprocessing import Array, Manager, Queue, Value
from queue import Empty
from time import time

from packaging.version import InvalidVersion, parse as parse_version

import config
from helperFunctions.process import (
    ExceptionSafeProcess,
    check_worker_exceptions,
    start_single_worker,
    stop_processes,
    terminate_process_and_children,
)
from helperFunctions.tag import TagColor
from plugins.base import BasePlugin
from typing import Iterable, TYPE_CHECKING
import ctypes

if TYPE_CHECKING:
    from objects.file import FileObject
    from helperFunctions.types import MpValue, MpArray

META_KEYS = {
    'tags',
    'summary',
    'analysis_date',
    'plugin_version',
    'system_version',
    'file_system_flag',
    'result',
}


def sanitize_processed_analysis(processed_analysis_entry: dict) -> dict:
    # Old analysis plugins (before AnalysisPluginV0) could write anything they want to processed_analysis.
    # We put everything the plugin wrote into a separate dict so that it matches the behavior of AnalysisPluginV0
    result = {}
    for key in list(processed_analysis_entry):
        if key in META_KEYS:
            continue

        result[key] = processed_analysis_entry.pop(key)

    processed_analysis_entry['result'] = result

    return processed_analysis_entry


class PluginInitException(Exception):  # noqa: N818
    def __init__(self, *args, plugin: AnalysisBasePlugin):
        self.plugin: AnalysisBasePlugin = plugin
        super().__init__(*args)


class AnalysisBasePlugin(BasePlugin):
    """
    This is the base plugin. All analysis plugins should be a subclass of this class.
    """

    # must be set by the plugin: NAME, FILE from BasePlugin and:
    DESCRIPTION: str = ''
    VERSION: str = ''

    # can be set by the plugin: DEPENDENCIES from BasePlugin and:
    RECURSIVE: bool = True  # If `True` (default) recursively analyze included files
    TIMEOUT: int = 300
    SYSTEM_VERSION: str | None = None
    MIME_BLACKLIST: Iterable[str] = ()
    MIME_WHITELIST: Iterable[str] = ()

    ANALYSIS_STATS_LIMIT = 1000

    def __init__(self, no_multithread=False, view_updater=None):
        super().__init__(plugin_path=self.FILE, view_updater=view_updater)
        self._check_plugin_attributes()
        self.additional_setup()
        self.in_queue: Queue[FileObject] = Queue()
        self.out_queue: Queue[FileObject] = Queue()
        self.stop_condition: MpValue[int] = Value('i', 0)  # type: ignore[assignment]
        self.workers = []
        self.thread_count = 1 if no_multithread else self._get_thread_count()
        self.active: list[MpValue[int]] = [Value('i', 0) for _ in range(self.thread_count)]  # type: ignore[misc]
        self.manager = Manager()
        self.analysis_stats: MpArray[ctypes.c_float] = Array(ctypes.c_float, self.ANALYSIS_STATS_LIMIT)
        self.analysis_stats_count: MpValue[int] = Value('i', 0)  # type: ignore[assignment]
        self.analysis_stats_index: MpValue[int] = Value('i', 0)  # type: ignore[assignment]

    def _get_thread_count(self):
        """
        Get the thread count from the config. If there is no configuration for this plugin use the default value.
        """
        default_process_count = config.backend.plugin_defaults.processes
        plugin_config = config.backend.plugin.get(self.NAME, None)
        return getattr(plugin_config, 'processes', default_process_count)

    def additional_setup(self):
        """
        This function can be implemented by the plugin to do initialization
        """

    def start(self):
        """Starts the plugin workers."""
        for process_index in range(self.thread_count):
            self.workers.append(start_single_worker(process_index, 'Analysis', self.worker))
        logging.debug(f'{self.NAME}: {len(self.workers)} worker threads started')

    def shutdown(self):
        """
        This function can be called to shut down all working threads
        """
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        self.in_queue.close()
        stop_processes(self.workers, timeout=10.0)  # give running analyses some time to finish
        self.out_queue.close()
        self.manager.shutdown()

    def _check_plugin_attributes(self):
        for attribute in ['FILE', 'NAME', 'VERSION']:
            if not bool(getattr(self, attribute, None)):
                raise PluginInitException(f'Plugin {self.NAME} is missing {attribute} in configuration', plugin=self)
        self._check_version(self.VERSION)
        if self.SYSTEM_VERSION:
            self._check_version(self.SYSTEM_VERSION, label='System version')

    def _check_version(self, version: str, label: str = 'Version'):
        try:
            parse_version(version)
        except InvalidVersion:
            raise PluginInitException(  # noqa: B904
                f'{label} "{version}" of plugin {self.NAME} is invalid', plugin=self
            )

    def add_job(self, fw_object: FileObject):
        if self._dependencies_are_unfulfilled(fw_object):
            logging.error(f'{fw_object.uid}: dependencies of plugin {self.NAME} not fulfilled')
        elif self._analysis_depth_not_reached_yet(fw_object):
            self.in_queue.put(fw_object)
            return
        self.out_queue.put(fw_object)

    def _dependencies_are_unfulfilled(self, fw_object: FileObject):
        # FIXME plugins can be in processed_analysis and could still be skipped, etc. -> need a way to verify that
        # FIXME the analysis ran successfully
        return any(dep not in fw_object.processed_analysis for dep in self.DEPENDENCIES)

    def _analysis_depth_not_reached_yet(self, fo):
        return self.RECURSIVE or fo.depth == 0

    def process_object(self, file_object):
        """
        This function must be implemented by the plugin
        """
        return file_object

    def analyze_file(self, file_object):
        fo = self.process_object(file_object)
        return self._add_plugin_version_and_timestamp_to_analysis_result(fo)

    def _add_plugin_version_and_timestamp_to_analysis_result(self, fo):
        fo.processed_analysis[self.NAME].update(self.init_dict())
        return fo

    # ---- internal functions ----

    def add_analysis_tag(  # noqa: PLR0913
        self, file_object, tag_name, value, color=TagColor.LIGHT_BLUE, propagate=False
    ):
        new_tag = {
            tag_name: {
                'value': value,
                'color': color,
                'propagate': propagate,
            },
            'root_uid': file_object.root_uid,
        }
        if 'tags' not in file_object.processed_analysis[self.NAME]:
            file_object.processed_analysis[self.NAME]['tags'] = new_tag
        else:
            file_object.processed_analysis[self.NAME]['tags'].update(new_tag)

    def init_dict(self) -> dict:
        result_update = {
            'analysis_date': time(),
            'plugin_version': self.VERSION,
            'result': {},
        }
        if self.SYSTEM_VERSION:
            result_update.update({'system_version': self.SYSTEM_VERSION})
        return result_update

    def process_next_object(self, task, result):
        task.processed_analysis.update({self.NAME: {}})
        finished_task = self.analyze_file(task)
        result.append(finished_task)

    @staticmethod
    def timeout_happened(process):
        return process.is_alive()

    def worker_processing_with_timeout(self, worker_id, next_task: FileObject):
        result = self.manager.list()
        process = ExceptionSafeProcess(target=self.process_next_object, args=(next_task, result))
        start = time()
        process.start()
        process.join(timeout=self.TIMEOUT)
        duration = time() - start
        if duration > 120:  # noqa: PLR2004
            logging.info(f'Analysis {self.NAME} on {next_task.uid} is slow: took {duration:.1f} seconds')
        self._update_duration_stats(duration)

        if self.timeout_happened(process):
            result_fo = self._handle_failed_analysis(next_task, process, worker_id, 'Timeout')
        elif process.exception:
            result_fo = self._handle_failed_analysis(next_task, process, worker_id, 'Exception')
        else:
            result_fo = result.pop()
            logging.debug(f'Worker {worker_id}: Finished {self.NAME} analysis on {next_task.uid}')

        processed_analysis_entry = result_fo.processed_analysis.pop(self.NAME)
        result_fo.processed_analysis[self.NAME] = sanitize_processed_analysis(processed_analysis_entry)
        self.out_queue.put(result_fo)

    def _update_duration_stats(self, duration: float):
        with self.analysis_stats.get_lock():
            self.analysis_stats[self.analysis_stats_index.value] = ctypes.c_float(duration)
        self.analysis_stats_index.value += 1
        if self.analysis_stats_index.value >= self.ANALYSIS_STATS_LIMIT:
            # if the stats array is full, overwrite the oldest result
            self.analysis_stats_index.value = 0
        if self.analysis_stats_count.value < self.ANALYSIS_STATS_LIMIT:
            self.analysis_stats_count.value += 1

    def _handle_failed_analysis(self, fw_object, process, worker_id, cause: str):
        terminate_process_and_children(process)
        fw_object.analysis_exception = (self.NAME, f'{cause} occurred during analysis')
        logging.error(f'Worker {worker_id}: {cause} during analysis {self.NAME} on {fw_object.uid}')

        return fw_object

    def worker(self, worker_id):
        logging.debug(f'started {self.NAME} worker {worker_id} (pid={os.getpid()})')
        while self.stop_condition.value == 0:
            try:
                next_task = self.in_queue.get(timeout=float(config.backend.block_delay))
                logging.debug(f'Worker {worker_id}: Begin {self.NAME} analysis on {next_task.uid}')
            except Empty:
                self.active[worker_id].value = 0
            else:
                self.active[worker_id].value = 1
                next_task.processed_analysis.update({self.NAME: {}})
                self.worker_processing_with_timeout(worker_id, next_task)

        logging.debug(f'worker {worker_id} stopped')

    def check_exceptions(self):
        return check_worker_exceptions(self.workers, 'Analysis', self.worker)

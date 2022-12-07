import logging
from multiprocessing import Manager, Queue, Value
from queue import Empty
from time import time

from config import cfg
from helperFunctions.process import (
    ExceptionSafeProcess,
    check_worker_exceptions,
    start_single_worker,
    stop_processes,
    terminate_process_and_children,
)
from helperFunctions.tag import TagColor
from objects.file import FileObject
from plugins.base import BasePlugin


class PluginInitException(Exception):
    def __init__(self, *args, plugin=None):
        self.plugin = plugin
        super().__init__(*args)


class AnalysisBasePlugin(BasePlugin):  # pylint: disable=too-many-instance-attributes
    '''
    This is the base plugin. All plugins should be subclass of this.
    '''

    # must be set by the plugin:
    FILE = None
    NAME = None
    DESCRIPTION = None
    VERSION = None

    # can be set by the plugin:
    RECURSIVE = True  # If `True` (default) recursively analyze included files
    TIMEOUT = 300
    SYSTEM_VERSION = None
    MIME_BLACKLIST = []
    MIME_WHITELIST = []

    def __init__(self, no_multithread=False, view_updater=None):
        super().__init__(plugin_path=self.FILE, view_updater=view_updater)
        self._check_plugin_attributes()
        self.additional_setup()
        self.in_queue = Queue()
        self.out_queue = Queue()
        self.stop_condition = Value('i', 0)
        self.workers = []
        self.thread_count = 1 if no_multithread else int(getattr(cfg, self.NAME, {}).get('threads', 1))
        self.active = [Value('i', 0) for _ in range(self.thread_count)]
        self.start_worker()

    def additional_setup(self):
        '''
        This function can be implemented by the plugin to do initialization
        '''

    def _check_plugin_attributes(self):
        for attribute in ['FILE', 'NAME', 'VERSION']:
            if getattr(self, attribute, None) is None:
                raise PluginInitException(f'Plugin {self.NAME} is missing {attribute} in configuration')

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

    def process_object(self, file_object):  # pylint: disable=no-self-use
        '''
        This function must be implemented by the plugin
        '''
        return file_object

    def analyze_file(self, file_object):
        fo = self.process_object(file_object)
        fo = self._add_plugin_version_and_timestamp_to_analysis_result(fo)
        return fo

    def _add_plugin_version_and_timestamp_to_analysis_result(self, fo):  # pylint: disable=invalid-name
        fo.processed_analysis[self.NAME].update(self.init_dict())
        return fo

    def shutdown(self):
        '''
        This function can be called to shut down all working threads
        '''
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        stop_processes(self.workers)
        self.in_queue.close()
        self.out_queue.close()

    # ---- internal functions ----

    def add_analysis_tag(self, file_object, tag_name, value, color=TagColor.LIGHT_BLUE, propagate=False):
        new_tag = {
            tag_name: {
                'value': value,
                'color': color,
                'propagate': propagate,
            },
            'root_uid': file_object.get_root_uid(),
        }
        if 'tags' not in file_object.processed_analysis[self.NAME]:
            file_object.processed_analysis[self.NAME]['tags'] = new_tag
        else:
            file_object.processed_analysis[self.NAME]['tags'].update(new_tag)

    def init_dict(self):
        result_update = {'analysis_date': time(), 'plugin_version': self.VERSION}
        if self.SYSTEM_VERSION:
            result_update.update({'system_version': self.SYSTEM_VERSION})
        return result_update

    def start_worker(self):
        for process_index in range(self.thread_count):
            self.workers.append(start_single_worker(process_index, 'Analysis', self.worker))
        logging.debug(f'{self.NAME}: {len(self.workers)} worker threads started')

    def process_next_object(self, task, result):
        task.processed_analysis.update({self.NAME: {}})
        finished_task = self.analyze_file(task)
        result.append(finished_task)

    @staticmethod
    def timeout_happened(process):
        return process.is_alive()

    def worker_processing_with_timeout(self, worker_id, next_task):
        manager = Manager()
        result = manager.list()
        process = ExceptionSafeProcess(target=self.process_next_object, args=(next_task, result))
        process.start()
        process.join(timeout=self.TIMEOUT)
        if self.timeout_happened(process):
            self._handle_failed_analysis(next_task, process, worker_id, 'Timeout')
        elif process.exception:
            self._handle_failed_analysis(next_task, process, worker_id, 'Exception')
        else:
            self.out_queue.put(result.pop())
            logging.debug(f'Worker {worker_id}: Finished {self.NAME} analysis on {next_task.uid}')

    def _handle_failed_analysis(self, fw_object, process, worker_id, cause: str):
        terminate_process_and_children(process)
        fw_object.analysis_exception = (self.NAME, f'{cause} occurred during analysis')
        logging.error(f'Worker {worker_id}: {cause} during analysis {self.NAME} on {fw_object.uid}')
        self.out_queue.put(fw_object)

    def worker(self, worker_id):
        while self.stop_condition.value == 0:
            try:
                next_task = self.in_queue.get(timeout=float(cfg.expert_settings.block_delay))
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

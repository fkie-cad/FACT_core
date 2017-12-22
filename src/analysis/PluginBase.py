import logging
import os
from multiprocessing import Queue, Value, Manager
from queue import Empty
from time import time

from common_helper_files import get_dir_of_file, get_files_in_dir, get_binary_from_file

from helperFunctions.dependency import get_unmatched_dependencys, schedule_dependencys
from helperFunctions.fileSystem import get_parent_dir
from helperFunctions.parsing import bcolors
from helperFunctions.process import ExceptionSafeProcess, terminate_process_and_childs
from storage.db_interface_view_sync import ViewUpdater
from helperFunctions.web_interface import ConnectTo


class BasePlugin(object):  # pylint: disable=too-many-instance-attributes
    '''
    This is the base plugin. All plugins should be subclass of this.
    recursive flag: If True (default) recursively analyze included files
    '''
    NAME = 'base'
    CONFIG_FILE = 'main.cfg'
    DEPENDENCYS = []
    VERSION = 'not set'

    timeout = None

    def __init__(self, plugin_adminstrator, config=None, recursive=True, no_multithread=False, timeout=300, offline_testing=False, plugin_path=None):  # pylint: disable=too-many-arguments
        self.history = set()
        self.config = config
        self.check_config(no_multithread)
        self.plugin_administrator = plugin_adminstrator
        self.recursive = recursive
        self.in_queue = Queue()
        self.out_queue = Queue()
        self.workload_index = Value('i', 0)
        self.stop_condition = Value('i', 0)
        self.workers = []
        if self.timeout is None:
            self.timeout = timeout
        if not offline_testing:
            self.start_worker()
        self.register_plugin()
        self._sync_view(plugin_path)

    def _sync_view(self, plugin_path):
        if plugin_path:
            view_source = self._get_view_file_path(plugin_path)
            if view_source is not None:
                view = get_binary_from_file(view_source)
                with ConnectTo(ViewUpdater, self.config) as connection:
                    connection.update_view(self.NAME, view)

    def _get_view_file_path(self, plugin_path):
        plugin_path = get_parent_dir(get_dir_of_file(plugin_path))
        view_files = get_files_in_dir(os.path.join(plugin_path, 'view'))
        if len(view_files) < 1:
            logging.debug('{}: No view available! Generic view will be used.'.format(self.NAME))
            return None
        elif len(view_files) > 1:
            logging.warning('{}: Plug-in provides more than one view! \'{}\' is used!'.format(self.NAME, view_files[0]))
        return view_files[0]

    def add_job(self, fw_object):
        if (fw_object.get_uid() in self.history) and (self.NAME not in fw_object.analysis_dependency):
            self.out_queue.put(fw_object)
            logging.debug('{} analysis already done -> skip: {}\n Analysis Dependencies: {}'.format(self.NAME, fw_object.get_uid(), fw_object.analysis_dependency))
        else:
            if self.recursive_condition_check(fw_object):
                if self.dependency_condition_check(fw_object):
                    self.history.add(fw_object.get_uid())
                    self.in_queue.put(fw_object)

    def recursive_condition_check(self, fo):
        if not self.recursive and fo.depth > 0:
            self.out_queue.put(fo)
            return False
        return True

    def dependency_condition_check(self, fo):
        unmatched_dependencies = get_unmatched_dependencys(fo.processed_analysis, self.DEPENDENCYS)
        if not unmatched_dependencies:
            return True
        else:
            logging.debug('{} rescheduled due to unmatched dependencies:\n {}'.format(fo.get_virtual_file_paths(), unmatched_dependencies))
            fo.scheduled_analysis = schedule_dependencys(fo.scheduled_analysis, unmatched_dependencies, self.NAME)
            fo.analysis_dependency = fo.analysis_dependency.union(set(unmatched_dependencies))
            logging.debug('new schedule for {}:\n {}\nAnalysis Dependencies: {}'.format(fo.get_virtual_file_paths(), fo.scheduled_analysis, fo.analysis_dependency))
            self.out_queue.put(fo)

    def process_object(self, file_object):  # pylint: disable=no-self-use
        '''
        This function must be implemented by the plugin
        '''
        return file_object

    def analyze_file(self, file_object):
        fo = self.process_object(file_object)
        fo = self._add_plugin_version_and_timestamp_to_analysis_result(fo)
        return fo

    def _add_plugin_version_and_timestamp_to_analysis_result(self, fo):
        fo.processed_analysis[self.NAME].update(self.init_dict())
        return fo

    def get_workload(self):
        '''
        This function returns the current number of objects in progress
        '''
        return self.workload_index.value

    def shutdown(self):
        '''
        This function can be called to shutdown all working threads
        '''
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        for process in self.workers:
            process.join()
        self.in_queue.close()
        self.out_queue.close()

    def init_dict(self):
        results = {}
        results['analysis_date'] = time()
        results['plugin_version'] = self.VERSION
        return results

# ---- internal functions ----

    def check_config(self, no_multihread):
        if self.NAME not in self.config:
            self.config.add_section(self.NAME)
        if 'threads' not in self.config[self.NAME] or no_multihread:
            self.config.set(self.NAME, 'threads', '1')

    def register_plugin(self):
        self.plugin_administrator.register_plugin(self.NAME, self)

    def start_worker(self):
        for process_index in range(int(self.config[self.NAME]['threads'])):
            self._start_single_worker_process(process_index)
        logging.debug('{}: {} worker threads started'.format(self.NAME, len(self.workers)))

    def _start_single_worker_process(self, process_index):
        process = ExceptionSafeProcess(target=self.worker, name='Analysis-Worker-{}'.format(process_index), args=(process_index,))
        process.start()
        self.workers.append(process)

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
        process.join(timeout=self.timeout)
        if self.timeout_happened(process):
            terminate_process_and_childs(process)
            self.out_queue.put(next_task)
            logging.warning('Worker {}: Timeout {} analysis on {}'.format(worker_id, self.NAME, next_task.get_uid()))
        elif process.exception:
            terminate_process_and_childs(process)
            raise process.exception[0]
        else:
            self.out_queue.put(result.pop())
            logging.debug('Worker {}: Finished {} analysis on {}'.format(worker_id, self.NAME, next_task.get_uid()))

    def worker(self, worker_id):
        while self.stop_condition.value == 0:
            try:
                next_task = self.in_queue.get(timeout=int(self.config['ExpertSettings']['block_delay']))
                logging.debug('Worker {}: Begin {} analysis on {}'.format(worker_id, self.NAME, next_task.get_uid()))
            except Empty:
                pass
            else:
                next_task.processed_analysis.update({self.NAME: {}})
                self.worker_processing_with_timeout(worker_id, next_task)

        logging.debug('worker {} stopped'.format(worker_id))

    def check_exceptions(self):
        return_value = False
        for worker in self.workers:
            if worker.exception:
                logging.error("{}Analysis worker {} caused exception{}".format(bcolors.FAIL, worker.name, bcolors.ENDC))
                logging.error(worker.exception[1])
                terminate_process_and_childs(worker)
                self.workers.remove(worker)
                if self.config.getboolean('ExpertSettings', 'throw_exceptions'):
                    return_value = True
                else:
                    process_index = worker.name.split('-')[2]
                    self._start_single_worker_process(process_index)
        return return_value

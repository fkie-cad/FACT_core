import logging
from multiprocessing import Queue, Value, Manager
from queue import Empty
from time import time

from helperFunctions.dependency import get_unmatched_dependencies, schedule_dependencies
from helperFunctions.parsing import bcolors
from helperFunctions.process import ExceptionSafeProcess, terminate_process_and_childs
from helperFunctions.tag import TagColor
from plugins.base import BasePlugin

class AnalysisBasePlugin(BasePlugin):  # pylint: disable=too-many-instance-attributes
    '''
    This is the base plugin. All plugins should be subclass of this.
    recursive flag: If True (default) recursively analyze included files
    '''
    CONFIG_FILE = 'main.cfg'
    VERSION = 'not set'

    timeout = None

    def __init__(self, plugin_administrator, config=None, recursive=True, no_multithread=False, timeout=300, offline_testing=False, plugin_path=None):  # pylint: disable=too-many-arguments
        super().__init__(plugin_administrator, config=config, plugin_path=plugin_path)
        self.history = set()
        self.check_config(no_multithread)
        self.recursive = recursive
        self.in_queue = Queue()
        self.out_queue = Queue()
        self.workload_index = Value('i', 0)
        self.stop_condition = Value('i', 0)
        self.workers = []
        if self.timeout is None:
            self.timeout = timeout
        self.register_plugin()
        if not offline_testing:
            self.start_worker()

    def add_job(self, fw_object):
        if self._job_is_already_done(fw_object):
            logging.debug('{} analysis already done -> skip: {}\n Analysis Dependencies: {}'.format(
                self.NAME, fw_object.get_uid(), fw_object.analysis_dependency))
        elif self._recursive_condition_is_set(fw_object):
            if self._dependencies_are_fulfilled(fw_object):
                self.history.add(fw_object.get_uid())
                self.in_queue.put(fw_object)
                return
            self._reschedule_job(fw_object)
        self.out_queue.put(fw_object)

    def _reschedule_job(self, fw_object):
        unmatched_dependencies = get_unmatched_dependencies([fw_object], self.DEPENDENCIES)
        logging.debug('{} rescheduled due to unmatched dependencies:\n {}'.format(fw_object.get_virtual_file_paths(), unmatched_dependencies))
        fw_object.scheduled_analysis = schedule_dependencies(fw_object.scheduled_analysis, unmatched_dependencies, self.NAME)
        fw_object.analysis_dependency = fw_object.analysis_dependency.union(set(unmatched_dependencies))
        logging.debug('new schedule for {}:\n {}\nAnalysis Dependencies: {}'.format(
            fw_object.get_virtual_file_paths(), fw_object.scheduled_analysis, fw_object.analysis_dependency))

    def _job_is_already_done(self, fw_object):
        return (fw_object.get_uid() in self.history) and (self.NAME not in fw_object.analysis_dependency)

    def _recursive_condition_is_set(self, fo):
        return self.recursive or fo.depth == 0

    def _dependencies_are_fulfilled(self, fo):
        return get_unmatched_dependencies([fo], self.DEPENDENCIES) == []

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

    def add_os_key_tag(self, file_object, tag_name, value, color = TagColor.LIGHT_BLUE, propagate = False):
        if 'tags' not in file_object.processed_analysis[self.NAME]:
            file_object.processed_analysis[self.NAME]['tags'] = {
                tag_name: {
                    'value': value,
                    'color': TagColor.LIGHT_BLUE,
                    'propagate': True,
                },
                'root_uid': file_object.get_root_uid()
            }
        else:
            new_tag = {
                tag_name: {
                    'value': value,
                    'color': TagColor.LIGHT_BLUE,
                    'propagate': True,
                },
                'root_uid': file_object.get_root_uid()
            }
            file_object.processed_analysis[self.NAME]['tags'].update(new_tag)

# ---- internal functions ----

    def init_dict(self):
        results = {}
        results['analysis_date'] = time()
        results['plugin_version'] = self.VERSION
        return results

    def check_config(self, no_multihread):
        if self.NAME not in self.config:
            self.config.add_section(self.NAME)
        if 'threads' not in self.config[self.NAME] or no_multihread:
            self.config.set(self.NAME, 'threads', '1')

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

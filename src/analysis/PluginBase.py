import logging
from multiprocessing import Manager, Queue, Value
from queue import Empty
from time import time

from helperFunctions.parsing import bcolors
from helperFunctions.process import ExceptionSafeProcess, terminate_process_and_childs
from helperFunctions.tag import TagColor
from objects.file import FileObject
from plugins.base import BasePlugin


class AnalysisBasePlugin(BasePlugin):  # pylint: disable=too-many-instance-attributes
    '''
    This is the base plugin. All plugins should be subclass of this.
    recursive flag: If True (default) recursively analyze included files
    '''
    VERSION = 'not set'
    SYSTEM_VERSION = None

    timeout = None

    def __init__(self, plugin_administrator, config=None, recursive=True, no_multithread=False, timeout=300, offline_testing=False, plugin_path=None):  # pylint: disable=too-many-arguments
        super().__init__(plugin_administrator, config=config, plugin_path=plugin_path)
        self.check_config(no_multithread)
        self.recursive = recursive
        self.in_queue = Queue()
        self.out_queue = Queue()
        self.stop_condition = Value('i', 0)
        self.workers = []
        if self.timeout is None:
            self.timeout = timeout
        self.register_plugin()
        if not offline_testing:
            self.start_worker()

    def add_job(self, fw_object: FileObject):
        if self._dependencies_are_unfulfilled(fw_object):
            logging.error('{}: dependencies of plugin {} not fulfilled'.format(fw_object.uid, self.NAME))
        elif self._analysis_depth_not_reached_yet(fw_object):
            self.in_queue.put(fw_object)
            return
        self.out_queue.put(fw_object)

    def _dependencies_are_unfulfilled(self, fw_object: FileObject):
        # FIXME plugins can be in processed_analysis and could still be skipped, etc. -> need a way to verify that
        # FIXME the analysis ran successfully
        return any(dep not in fw_object.processed_analysis for dep in self.DEPENDENCIES)

    def _analysis_depth_not_reached_yet(self, fo):
        return self.recursive or fo.depth == 0

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

# ---- internal functions ----

    def add_analysis_tag(self, file_object, tag_name, value, color=TagColor.LIGHT_BLUE, propagate=False):
        new_tag = {
            tag_name: {
                'value': value,
                'color': color,
                'propagate': propagate,
            },
            'root_uid': file_object.get_root_uid()
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

    def check_config(self, no_multithread):
        if self.NAME not in self.config:
            self.config.add_section(self.NAME)
        if 'threads' not in self.config[self.NAME] or no_multithread:
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
            logging.warning('Worker {}: Timeout {} analysis on {}'.format(worker_id, self.NAME, next_task.uid))
        elif process.exception:
            terminate_process_and_childs(process)
            raise process.exception[0]
        else:
            self.out_queue.put(result.pop())
            logging.debug('Worker {}: Finished {} analysis on {}'.format(worker_id, self.NAME, next_task.uid))

    def worker(self, worker_id):
        while self.stop_condition.value == 0:
            try:
                next_task = self.in_queue.get(timeout=float(self.config['ExpertSettings']['block_delay']))
                logging.debug('Worker {}: Begin {} analysis on {}'.format(worker_id, self.NAME, next_task.uid))
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
                logging.error('{}Analysis worker {} caused exception{}'.format(bcolors.FAIL, worker.name, bcolors.ENDC))
                logging.error(worker.exception[1])
                terminate_process_and_childs(worker)
                self.workers.remove(worker)
                if self.config.getboolean('ExpertSettings', 'throw_exceptions'):
                    return_value = True
                else:
                    process_index = worker.name.split('-')[2]
                    self._start_single_worker_process(process_index)
        return return_value

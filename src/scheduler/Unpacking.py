import logging
from contextlib import suppress
from multiprocessing import Queue, Value
from queue import Empty
from time import sleep

from helperFunctions.parsing import bcolors
from helperFunctions.process import ExceptionSafeProcess, terminate_process_and_childs
from storage.db_interface_common import MongoInterfaceCommon
from unpacker.unpack import Unpacker


class UnpackingScheduler(object):
    '''
    This scheduler performs unpacking on firmware objects
    '''

    def __init__(self, config=None, post_unpack=None, analysis_workload=None, db_interface=None):
        self.config = config
        self.stop_condition = Value('i', 0)
        self.throttle_condition = Value('i', 0)
        self.get_analysis_workload = analysis_workload
        self.in_queue = Queue()
        self.work_load_counter = 25
        self.workers = []
        self.post_unpack = post_unpack
        self.db_interface = MongoInterfaceCommon(config) if not db_interface else db_interface
        self.drop_cached_locks()
        self.start_unpack_workers()
        self.start_work_load_monitor()
        logging.info('Unpacker Module online')

    def drop_cached_locks(self):
        self.db_interface.drop_unpacking_locks()

    def add_task(self, fo):
        '''
        schedule a firmware_object for unpacking
        '''
        self.in_queue.put(fo)

    def get_scheduled_workload(self):
        return {'unpacking_queue': self.in_queue.qsize()}

    def shutdown(self):
        '''
        shutdown the scheduler
        '''
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        for worker in self.workers:
            worker.join()
        self.in_queue.close()
        logging.info('Unpacker Module offline')

# ---- internal functions ----

    def start_unpack_workers(self):
        logging.debug('Starting {} working threads'.format(int(self.config['unpack']['threads'])))
        for process_index in range(int(self.config['unpack']['threads'])):
            self._start_single_worker(process_index)

    def unpack_worker(self, worker_id):
        unpacker = Unpacker(self.config, worker_id=worker_id, db_interface=self.db_interface)
        while self.stop_condition.value == 0:
            with suppress(Empty):
                fo = self.in_queue.get(timeout=float(self.config['ExpertSettings']['block_delay']))
                extracted_objects = unpacker.unpack(fo)
                logging.debug('[worker {}] unpacking of {} complete: {} files extracted'.format(worker_id, fo.uid, len(extracted_objects)))
                self.post_unpack(fo)
                self.schedule_extracted_files(extracted_objects)

    def schedule_extracted_files(self, object_list):
        for item in object_list:
            self._add_object_to_unpack_queue(item)

    def _add_object_to_unpack_queue(self, item):
        while self.stop_condition.value == 0:
            if self.throttle_condition.value == 0:
                self.in_queue.put(item)
                break
            else:
                logging.debug('throttle down unpacking to reduce memory consumption...')
                sleep(5)

    def start_work_load_monitor(self):
        logging.debug('Start work load monitor...')
        process = ExceptionSafeProcess(target=self._work_load_monitor)
        process.start()
        self.workers.append(process)

    def _work_load_monitor(self):
        while self.stop_condition.value == 0:
            workload = self._get_combined_analysis_workload()
            unpack_queue_size = self.in_queue.qsize()

            if self.work_load_counter >= 25:
                self.work_load_counter = 0
                log_function = logging.info
            else:
                self.work_load_counter += 1
                log_function = logging.debug
            log_function('{}Queue Length (Analysis/Unpack): {} / {}{}'.format(bcolors.WARNING, workload, unpack_queue_size, bcolors.ENDC))

            if workload < int(self.config['ExpertSettings']['unpack_throttle_limit']):
                self.throttle_condition.value = 0
            else:
                self.throttle_condition.value = 1
            sleep(2)

    def _get_combined_analysis_workload(self):
        if self.get_analysis_workload is not None:
            current_analysis_workload = self.get_analysis_workload()
            return sum(current_analysis_workload.values())
        return 0

    def check_exceptions(self):
        return_value = False
        for worker in self.workers:
            if worker.exception:
                logging.error("{}Worker Exception Found!!{}".format(bcolors.FAIL, bcolors.ENDC))
                logging.error(worker.exception[1])
                terminate_process_and_childs(worker)
                self.workers.remove(worker)

                if self.config.getboolean('ExpertSettings', 'throw_exceptions'):
                    return_value = True
                else:
                    process_index = worker.name.split('-')[2]
                    self._start_single_worker(process_index)
        return return_value

    def _start_single_worker(self, process_index):
        process = ExceptionSafeProcess(target=self.unpack_worker,
                                       name='Unpacking-Worker-{}'.format(process_index),
                                       args=(process_index,))
        process.start()
        self.workers.append(process)

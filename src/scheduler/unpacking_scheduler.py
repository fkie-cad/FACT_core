import logging
import os
from contextlib import suppress
from multiprocessing import Queue, Value
from queue import Empty
from time import sleep

from config import cfg
from helperFunctions.logging import TerminalColors, color_string
from helperFunctions.process import check_worker_exceptions, new_worker_was_started, start_single_worker, stop_processes
from unpacker.unpack import Unpacker

THROTTLE_INTERVAL = 2


class UnpackingScheduler:  # pylint: disable=too-many-instance-attributes
    '''
    This scheduler performs unpacking on firmware objects
    '''

    def __init__(self, post_unpack=None, analysis_workload=None, fs_organizer=None, unpacking_locks=None):
        self.stop_condition = Value('i', 0)
        self.throttle_condition = Value('i', 0)
        self.get_analysis_workload = analysis_workload
        self.fs_organizer = fs_organizer
        self.in_queue = Queue()
        self.work_load_counter = 25
        self.workers = []
        self.post_unpack = post_unpack
        self.unpacking_locks = unpacking_locks

    def start(self):
        self.start_unpack_workers()
        self.work_load_process = self.start_work_load_monitor()
        logging.info('Unpacker Module online')

    def shutdown(self):
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        self.in_queue.close()
        stop_processes(
            self.workers + [self.work_load_process], max(cfg.expert_settings.block_delay, THROTTLE_INTERVAL) + 1
        )
        logging.info('Unpacker Module offline')

    def add_task(self, fo):
        '''
        schedule a firmware_object for unpacking
        '''
        self.in_queue.put(fo)

    def get_scheduled_workload(self):
        return {'unpacking_queue': self.in_queue.qsize()}

    # ---- internal functions ----

    def start_unpack_workers(self):
        threads = cfg.unpack.threads
        logging.debug(f'Starting {threads} working threads')
        for process_index in range(threads):
            self.workers.append(start_single_worker(process_index, 'Unpacking', self.unpack_worker))

    def unpack_worker(self, worker_id):
        unpacker = Unpacker(
            worker_id=worker_id,
            fs_organizer=self.fs_organizer,
            unpacking_locks=self.unpacking_locks,
        )
        while self.stop_condition.value == 0:
            with suppress(Empty):
                fo = self.in_queue.get(timeout=cfg.expert_settings.block_delay)
                extracted_objects = unpacker.unpack(fo)
                logging.debug(
                    f'[worker {worker_id}] unpacking of {fo.uid} complete: {len(extracted_objects)} files extracted'
                )
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
            logging.debug('throttle down unpacking to reduce memory consumption...')
            sleep(5)

    def start_work_load_monitor(self):
        logging.debug('Start work load monitor...')
        return start_single_worker(None, 'unpack-load', self._work_load_monitor)

    def _work_load_monitor(self):
        logging.debug(f'Started unpacking work load monitor (pid={os.getpid()})')
        while self.stop_condition.value == 0:
            workload = self._get_combined_analysis_workload()
            unpack_queue_size = self.in_queue.qsize()

            if self.work_load_counter >= 25:
                self.work_load_counter = 0
                log_function = logging.info
            else:
                self.work_load_counter += 1
                log_function = logging.debug
            log_function(
                color_string(
                    f'Queue Length (Analysis/Unpack): {workload} / {unpack_queue_size}', TerminalColors.WARNING
                )
            )

            if workload < cfg.expert_settings.unpack_throttle_limit:
                self.throttle_condition.value = 0
            else:
                self.throttle_condition.value = 1
            sleep(THROTTLE_INTERVAL)

    def _get_combined_analysis_workload(self):
        if self.get_analysis_workload is not None:
            return self.get_analysis_workload()
        return 0

    def check_exceptions(self):
        shutdown = check_worker_exceptions(self.workers, 'Unpacking', self.unpack_worker)

        list_with_load_process = [
            self.work_load_process,
        ]
        shutdown |= check_worker_exceptions(list_with_load_process, 'unpack-load', self._work_load_monitor)
        if new_worker_was_started(new_process=list_with_load_process[0], old_process=self.work_load_process):
            self.work_load_process = list_with_load_process.pop()

        return shutdown

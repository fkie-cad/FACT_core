from __future__ import annotations

import logging
import os
from multiprocessing import Queue, Value
from queue import Empty

import config
from compare.compare import Compare
from helperFunctions.data_conversion import convert_compare_id_to_list
from helperFunctions.process import check_worker_exceptions, new_worker_was_started, start_single_worker
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_comparison import ComparisonDbInterface


class ComparisonScheduler:
    '''
    This module handles all request regarding comparisons
    '''

    def __init__(self, db_interface=None, admin_db_interface=None, callback=None):
        self.db_interface = db_interface if db_interface else ComparisonDbInterface()
        self.db_admin_interface = admin_db_interface or AdminDbInterface()
        self.stop_condition = Value('i', 1)
        self.in_queue = Queue()
        self.callback = callback
        self.comparison_module = Compare(db_interface=self.db_interface)
        self.worker = None

    def start(self):
        self.stop_condition.value = 0
        self.worker = start_single_worker(0, 'Comparison', self._comparison_scheduler_worker)
        logging.info('Comparison scheduler online')

    def shutdown(self):
        logging.debug('Shutting down comparison scheduler')
        if self.stop_condition.value == 0:
            self.stop_condition.value = 1
            self.worker.join()
        self.in_queue.close()
        logging.info('Comparison scheduler offline')

    def add_task(self, comparison_task):
        comparison_id, redo = comparison_task
        if not self.db_interface.objects_exist(comparison_id):
            logging.error(f'Trying to start comparison but not all objects exist: {comparison_id}')
            return
        logging.debug(f'Scheduling for comparison: {comparison_id}')
        self.in_queue.put((comparison_id, redo))

    def _comparison_scheduler_worker(self, worker_id: int):
        logging.debug(f'Started comparison worker {worker_id} (pid={os.getpid()})')
        comparisons_done = set()
        while self.stop_condition.value == 0:
            self._compare_single_run(comparisons_done)
        logging.debug(f'Stopped comparison worker {worker_id}')

    def _compare_single_run(self, comparisons_done):
        try:
            comparison_id, redo = self.in_queue.get(timeout=config.backend.block_delay)
        except Empty:
            return
        if self._comparison_should_start(comparison_id, redo, comparisons_done):
            if redo:
                self.db_admin_interface.delete_comparison(comparison_id)
            comparisons_done.add(comparison_id)
            self._process_comparison(comparison_id)
            if self.callback:
                self.callback()

    def _process_comparison(self, comparison_id: str):
        try:
            self.db_interface.add_comparison_result(
                self.comparison_module.compare(convert_compare_id_to_list(comparison_id))
            )
        except Exception:  # pylint: disable=broad-except
            logging.error(f'Fatal error in comparison process for {comparison_id}', exc_info=True)

    @staticmethod
    def _comparison_should_start(uid, redo, comparisons_done):
        return redo or uid not in comparisons_done

    def check_exceptions(self):
        processes_to_check = [self.worker]
        shutdown = check_worker_exceptions(processes_to_check, 'Comparison', self._comparison_scheduler_worker)
        if not shutdown and new_worker_was_started(new_process=processes_to_check[0], old_process=self.worker):
            self.worker = processes_to_check.pop()
        return shutdown

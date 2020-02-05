import logging
from multiprocessing import Queue, Value
from queue import Empty

from compare.compare import Compare
from helperFunctions.dataConversion import convert_compare_id_to_list
from helperFunctions.process import ExceptionSafeProcess, check_worker_exceptions, new_worker_was_started
from storage.db_interface_compare import CompareDbInterface, FactCompareException


class CompareScheduler:
    '''
    This module handles all request regarding compares
    '''

    def __init__(self, config=None, db_interface=None, testing=False, callback=None):
        self.config = config
        self.db_interface = db_interface if db_interface else CompareDbInterface(config=config)
        self.stop_condition = Value('i', 1)
        self.in_queue = Queue()
        self.callback = callback
        self.compare_module = Compare(config=self.config, db_interface=self.db_interface)
        self.worker = ExceptionSafeProcess(target=self._compare_scheduler_main)
        if not testing:
            self.start()

    def start(self):
        self.stop_condition.value = 0
        self.worker.start()
        logging.info('Compare Scheduler online...')

    def shutdown(self):
        '''
        shutdown the scheduler
        '''
        logging.debug('Shutting down...')
        if getattr(self.db_interface, 'shutdown', False):
            self.db_interface.shutdown()
        if self.stop_condition.value == 0:
            self.stop_condition.value = 1
            self.worker.join()
        self.in_queue.close()
        logging.info('Compare Scheduler offline')

    def add_task(self, compare_task):
        compare_id, redo = compare_task
        try:
            self.db_interface.check_objects_exist(compare_id)
        except FactCompareException as exception:
            return exception.get_message()  # FIXME: return value gets ignored by backend intercom
        logging.debug('Schedule for compare: {}'.format(compare_id))
        self.in_queue.put((compare_id, redo))
        return None

    def _compare_scheduler_main(self):
        compares_done = set()
        while self.stop_condition.value == 0:
            self._compare_single_run(compares_done)
        logging.debug('Compare Thread terminated')

    def _compare_single_run(self, compares_done):
        try:
            compare_id, redo = self.in_queue.get(timeout=float(self.config['ExpertSettings']['block_delay']))
        except Empty:
            pass
        else:
            if self._decide_whether_to_process(compare_id, redo, compares_done):
                if redo:
                    self.db_interface.delete_old_compare_result(compare_id)
                compares_done.add(compare_id)
                self._process_compare(compare_id)
                if self.callback:
                    self.callback()

    def _process_compare(self, compare_id):
        result = self.compare_module.compare(convert_compare_id_to_list(compare_id))
        if isinstance(result, dict):
            self.db_interface.add_compare_result(result)
        else:
            logging.error(result)

    @staticmethod
    def _decide_whether_to_process(uid, redo, compares_done):
        return redo or uid not in compares_done

    def check_exceptions(self):
        processes_to_check = [self.worker]
        shutdown = check_worker_exceptions(processes_to_check, 'Compare', self.config, self._compare_scheduler_main)
        if not shutdown and new_worker_was_started(new_process=processes_to_check[0], old_process=self.worker):
            self.worker = processes_to_check.pop()
        return shutdown

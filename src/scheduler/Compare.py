import logging
from multiprocessing import Value, Queue
from queue import Empty

from compare.compare import Compare
from helperFunctions.dataConversion import string_list_to_list
from helperFunctions.parsing import bcolors
from helperFunctions.process import ExceptionSafeProcess, terminate_process_and_childs
from storage.db_interface_compare import CompareDbInterface


class CompareScheduler(object):
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
        err = self.db_interface.object_existence_quick_check(compare_id)
        if err is not None:
            return err
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
            compare_id, redo = self.in_queue.get(timeout=int(self.config['ExpertSettings']['block_delay']))
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
        result = self.compare_module.compare(string_list_to_list(compare_id))
        if isinstance(result, dict):
            self.db_interface.add_compare_result(result)
        else:
            logging.error(result)

    @staticmethod
    def _decide_whether_to_process(uid, redo, compares_done):
        if redo or uid not in compares_done:
            return True
        return False

    def check_exceptions(self):
        return_value = False
        if self.worker.exception:
            logging.error("{}Worker Exception Found!!{}".format(bcolors.FAIL, bcolors.ENDC))
            logging.error(self.worker.exception[1])
            if self.config.getboolean('ExpertSettings', 'throw_exceptions'):
                return_value = True
                terminate_process_and_childs(self.worker)
        return return_value

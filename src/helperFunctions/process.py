import functools
import logging
import os
import signal
import traceback
from configparser import ConfigParser
from contextlib import suppress
from multiprocessing import Pipe, Process, pool
from typing import Callable, List, Optional

import psutil

from helperFunctions.logging import TerminalColors, color_string


def no_operation(*_):
    '''
    No Operation
    '''


def complete_shutdown(message=None):
    if message is not None:
        logging.error(message)
    logging.error('SHUTTING DOWN SYSTEM')
    _pid = os.getpid()
    _pgid = os.getpgid(_pid)
    os.killpg(_pgid, 9)


def timeout(max_timeout_seconds):
    def timeout_decorator(item):
        @functools.wraps(item)
        def func_wrapper(*args, **kwargs):
            this_pool = pool.ThreadPool(processes=1)
            async_result = this_pool.apply_async(item, args, kwargs)
            # raises a TimeoutError if execution exceeds max_timeout
            return async_result.get(max_timeout_seconds)
        return func_wrapper
    return timeout_decorator


class ExceptionSafeProcess(Process):
    def __init__(self, *args, **kwargs):
        Process.__init__(self, *args, **kwargs)
        self._receive_pipe, self._send_pipe = Pipe()
        self._exception = None
        self.called_function = kwargs.get('target')

    def run(self):
        try:
            Process.run(self)
            self._send_pipe.send(None)
        except Exception as exception:  # pylint: disable=broad-except
            trace = traceback.format_exc()
            self._send_pipe.send((exception, trace))
            raise exception

    @property
    def exception(self):
        if self._receive_pipe.poll():
            self._exception = self._receive_pipe.recv()
        return self._exception


def terminate_process_and_childs(process):
    process.terminate()
    _terminate_orphans(process)
    process.join()


def _terminate_orphans(process):
    with suppress(psutil.NoSuchProcess):
        parent = psutil.Process(process.pid)
        for child in parent.children(recursive=True):
            child.send_signal(signal.SIGTERM)


def start_single_worker(process_index, label: str, function: Callable) -> ExceptionSafeProcess:
    process = ExceptionSafeProcess(
        target=function,
        name='{}-Worker-{}'.format(label, process_index),
        args=(process_index,) if process_index is not None else tuple()
    )
    process.start()
    return process


def check_worker_exceptions(process_list: List[ExceptionSafeProcess], worker_label: str,
                            config: Optional[ConfigParser] = None, worker_function: Optional[Callable] = None) -> bool:
    return_value = False
    for worker_process in process_list:
        if worker_process.exception:
            logging.error(color_string('Exception in {} process'.format(worker_label), TerminalColors.FAIL))
            logging.error(worker_process.exception[1])
            terminate_process_and_childs(worker_process)
            process_list.remove(worker_process)
            if config is None or config.getboolean('ExpertSettings', 'throw_exceptions'):
                return_value = True
            elif worker_function is not None:
                process_index = int(worker_process.name.split('-')[-1])
                logging.warning(
                    color_string('restarting {} {} process'.format(worker_label, process_index), TerminalColors.WARNING)
                )
                process_list.append(start_single_worker(process_index, worker_label, worker_function))
    return return_value


def new_worker_was_started(new_process: ExceptionSafeProcess, old_process: ExceptionSafeProcess) -> bool:
    return new_process != old_process

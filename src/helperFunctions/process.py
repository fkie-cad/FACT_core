import functools
import logging
import os
import signal
import traceback
from contextlib import suppress
from multiprocessing import pool, Process, Pipe

import psutil


def no_operation(*_):
    '''
    No Operation
    '''
    pass


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

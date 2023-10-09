from __future__ import annotations

import logging
import os
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from multiprocessing import Pipe, Process
from signal import SIGTERM
from threading import Thread

import psutil

import config
from helperFunctions.logging import TerminalColors, color_string
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


def complete_shutdown(message: str | None = None) -> None:
    """
    Shutdown all FACT processes (of the currently running component) by sending a signal to the process group.

    :param message: Optional message to be displayed before the shutdown.
    """
    if message is not None:
        logging.warning(message)
    logging.critical('SHUTTING DOWN SYSTEM')
    _stop_remaining_fact_processes()


def _stop_remaining_fact_processes():
    """Find subprocesses of this process group and stop them."""
    pgid = os.getpgrp()
    futures = []
    with ThreadPoolExecutor() as pool:
        for proc in psutil.process_iter():
            try:
                if os.getpgid(proc.pid) == pgid and proc.pid != pgid:
                    futures.append(pool.submit(_stop_process_by_pid, proc.pid))
            except ProcessLookupError:
                pass
        for future in futures:
            future.result()  # call result to make sure all threads are finished and there are no exceptions


def _stop_process_by_pid(pid: int):
    try:
        proc = psutil.Process(pid)
        try:
            proc.wait(5)
        except psutil.TimeoutExpired as err:
            logging.warning(f'Timeout while waiting for process to shut down: {err} -> kill')
            if proc and proc.is_running():
                proc.kill()
    except (ChildProcessError, psutil.NoSuchProcess):
        pass  # process shut down itself in the meantime -> nothing to do


class ExceptionSafeProcess(Process):
    """
    ExceptionSafeProcess is a subtype of ``multiprocessing.Process`` with added exception handling.
    Opposed to what the name may suggest, the class does not make the process impervious to exceptions.
    Instead, it retrieves the exception of the subprocess and re-raises it. This allows reconstructing what
    happened in the subprocess.

    The parameters for creating an instance of the class are the same as for ``multiprocessing.Process``
    (see `Python docs`_).

    .. _Python docs: https://docs.python.org/3/library/multiprocessing.html#multiprocessing.Process
    """

    def __init__(self, *args, reraise: bool = True, **kwargs):
        super().__init__(*args, **kwargs)
        self._receive_pipe, self._send_pipe = Pipe()
        self._exception = None
        self._reraise = reraise

    def run(self):
        """
        Starts the execution of the process. Any exception happening in the process will be reraised and may
        be retrieved by accessing ``ExceptionSafeProcess.exception``.
        """
        try:
            Process.run(self)
            self._send_pipe.send(None)
        except Exception as exception:
            trace = traceback.format_exc()
            self._send_pipe.send((exception, trace))
            if self._reraise:
                raise exception

    @property
    def exception(self) -> tuple[Exception, str] | None:
        """
        The exception that occurred in the process during execution and the respective stack trace.
        Is ``None`` if no exception occurred or the process was no yet executed.

        :return: A tuple containing the exception and the stack trace or  ``None``.
        """
        if self._receive_pipe.poll():
            self._exception = self._receive_pipe.recv()
        return self._exception


def terminate_process_and_children(process: Process) -> None:
    """
    Terminate a process and all of its child processes.

    :param process: The process to be terminated.
    """
    process.terminate()
    _terminate_orphans(process)
    process.join()


def _terminate_orphans(process):
    with suppress(psutil.NoSuchProcess):
        parent = psutil.Process(process.pid)
        for child in parent.children(recursive=True):
            child.send_signal(SIGTERM)


def start_single_worker(process_index: int, label: str, function: Callable) -> ExceptionSafeProcess:
    """
    Starts a new worker process executing ``function`` and returns it. Used for unpacking and analysis workers in the
    FACT backend.

    :param process_index: The index of the process in the process list of the scheduler.
    :param label: A label used for logging (e.g. `Analysis` or `Unpacking`).
    :param function: The function, that gets executed by the worker process.
    :return: The running process.
    """
    process = ExceptionSafeProcess(
        target=function,
        name=f'{label}-Worker-{process_index}',
        args=(process_index,) if process_index is not None else (),
    )
    process.start()
    return process


def check_worker_exceptions(
    process_list: list[ExceptionSafeProcess],
    worker_label: str,
    worker_function: Callable | None = None,
) -> bool:
    """
    Iterate over the `process_list` and check if exceptions occurred. In case of an exception, the process and its
    children will be terminated. If ``throw_exceptions`` in the FACT configuration is set to `false`, the worker
    may be restarted by passing a function (if the value is not set, the worker will not be restarted). In this case,
    the function will always return ``False``. If ``throw_exceptions`` is set to `true` and an exception occurs,
    the worker will not be restarted and the return value is ``True``.

    :param process_list: A list of worker processes.
    :param worker_label: A label used for logging (e.g. `Analysis` or `Unpacking`).
    :param worker_function: A function used for restarting the worker (optional).
    :return: ``True`` if an exception occurred in any process and ``throw_exceptions`` in the FACT configuration is
             set to `true` and ``False`` otherwise.
    """
    return_value = False
    for worker_process in process_list:
        if worker_process.exception:
            _, stack_trace = worker_process.exception
            logging.error(color_string(f'Exception in {worker_label} process:\n{stack_trace}', TerminalColors.FAIL))
            terminate_process_and_children(worker_process)
            process_list.remove(worker_process)
            if config.backend.throw_exceptions:
                return_value = True
            elif worker_function is not None:
                process_index = int(worker_process.name.split('-')[-1])
                logging.warning(
                    color_string(f'restarting {worker_label} {process_index} process', TerminalColors.WARNING)
                )
                process_list.append(start_single_worker(process_index, worker_label, worker_function))
    return return_value


def new_worker_was_started(new_process: ExceptionSafeProcess, old_process: ExceptionSafeProcess) -> bool:
    """
    Check if a worker process was restarted by comparing old and new process.

    :param new_process: The new process.
    :param old_process: The old process.
    :return: ``True`` if the processes match and ``False`` otherwise.
    """
    return new_process != old_process


def stop_processes(processes: list[Process], timeout: float = 10.0):
    """
    Try to stop processes gracefully in parallel. If a process does not stop until `timeout` is reached, kill it.

    :param processes: The list of processes that should be stopped.
    :param timeout: Timeout for joining the process in seconds.
    """
    thread_list = []
    for process in processes:
        thread = Thread(target=stop_process, args=(process, timeout))
        thread.start()
        thread_list.append(thread)
    for thread in thread_list:
        thread.join()


def stop_process(process: Process, timeout: float = 10.0):
    """Try to stop a single process gracefully. If it does not stop until `timeout` is reached, kill it."""
    process.join(timeout=timeout)
    if process.is_alive():
        process.kill()

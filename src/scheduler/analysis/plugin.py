import ctypes
import io
import logging
import multiprocessing as mp
import multiprocessing.connection
import queue
import signal
import time
import traceback
import typing

import psutil
import pydantic
from pydantic import BaseModel

import config
from objects.file import FileObject
from plugins import analysis
from statistic.analysis_stats import ANALYSIS_STATS_LIMIT
from storage.fsorganizer import FSOrganizer


class PluginRunner:
    # pylint:disable=too-many-instance-attributes
    class Config(BaseModel):
        """A class containing all parameters of the runner"""

        process_count: int
        #: Timeout in seconds after which the analysis is aborted
        timeout: int

    class Task(BaseModel):
        """Contains all information a :py:class:`PluginWorker` needs to analyze a file."""

        #: The virtual file path of the file object
        #: See :py:class:`FileObject`.
        virtual_file_path: typing.Dict
        #: The path of the file on the disk
        path: str
        #: A dictionary containing plugin names as keys and their analysis as value.
        dependencies: typing.Dict
        #: The schedulers state associated with the file that is analyzed.
        #: Here it is just the whole FileObject
        # We need this because the scheduler is using multiple processes which
        # communicate via multiprocessing.Queue's.
        # Our implementation has no "master" process which contains all the
        # state but rather the state is passed through the queues,
        # even if a process (like PluginRunner) does not need all state (e.g.
        # FileObject.scheduled_analysis)
        scheduler_state: FileObject

        class Config:
            arbitrary_types_allowed = True

    def __init__(
        self,
        plugin: analysis.PluginV0,
        config: Config,
        schemata: typing.Dict[str, pydantic.BaseModel],
    ):
        self._plugin = plugin
        self._config = config
        self._schemata = schemata

        self._in_queue: mp.Queue = mp.Queue()
        #: Workers put the ``Task.scheduler_state`` and the finished analysis in the out_queue
        self.out_queue: mp.Queue = mp.Queue()
        self.out_queue.close()

        self.stats = mp.Array(ctypes.c_float, ANALYSIS_STATS_LIMIT)
        self.stats_count = mp.Value('i', 0)
        self._stats_idx = mp.Value('i', 0)

        self._fsorganizer = FSOrganizer()

        worker_config = Worker.Config(
            timeout=self._config.timeout,
        )
        self._workers = [
            Worker(
                plugin=plugin,
                worker_config=worker_config,
                in_queue=self._in_queue,
                out_queue=self.out_queue,
                stats=self.stats,
                stats_count=self.stats_count,
                stats_idx=self._stats_idx,
            )
            for _ in range(self._config.process_count)
        ]

    def get_queue_len(self) -> int:
        return self._in_queue.qsize()

    def get_active_worker_count(self) -> int:
        """Returns the amount of workers that currently analyze a file"""
        return sum([worker.is_alive() for worker in self._workers])

    def start(self):
        for worker in self._workers:
            worker.start()

    def shutdown(self):
        for worker in self._workers:
            worker.terminate()

    def queue_analysis(self, file_object: FileObject):
        """Queues the analysis of ``file_object`` with ``self._plugin``.
        The caller of this method has to ensure that the dependencies are fulfilled.
        """
        dependencies = {}
        for dependency in self._plugin.metadata.dependencies:
            Schema = self._schemata[dependency]
            # Try to convert to the schema defined by the plugin
            result = file_object.processed_analysis[dependency]['result']
            dependencies[dependency] = Schema(**result)

        logging.debug(f'Queueing analysis for {file_object.uid}')
        self._in_queue.put(
            PluginRunner.Task(
                virtual_file_path=file_object.virtual_file_path,
                path=self._fsorganizer.generate_path(file_object),
                dependencies=dependencies,
                scheduler_state=file_object,
            )
        )


class Worker(mp.Process):
    """A process that executes a plugin in a child process."""

    # pylint: disable=too-many-arguments

    # The amount of time in seconds that a worker has to complete when it shall terminate.
    # We cannot rely on the plugins timeout as this might be too large.
    SIGTERM_TIMEOUT = 5

    class TimeoutError(Exception):
        def __init__(self, timeout: float):
            self.timeout = timeout

    class Config(BaseModel):
        """A class containing all parameters of the worker"""

        #: Timeout in seconds after which the analysis is aborted
        timeout: int

    def __init__(
        self,
        plugin: analysis.PluginV0,
        worker_config: Config,
        in_queue: mp.Queue,
        out_queue: mp.Queue,
        stats: mp.Array,
        stats_count: mp.Value,
        stats_idx: mp.Value,
    ):
        super().__init__(name=f'{plugin.metadata.name} worker')
        self._plugin = plugin
        self._worker_config = worker_config

        self._in_queue = in_queue
        self._in_queue.close()
        self._out_queue = out_queue

        self._stats = stats
        self._stats_count = stats_count
        self._stats_idx = stats_idx

        # Used for statistics
        self._is_working = mp.Value('i')
        self._is_working.value = 0

    def is_working(self):
        return self._is_working.value != 0

    # pylint:disable=too-complex
    def run(self):
        run = True
        recv_conn, send_conn = mp.Pipe(duplex=False)

        child_process = None

        def _handle_sigterm(signum, frame):
            del signum, frame
            logging.critical(f'{self} received SIGTERM. Shutting down.')
            nonlocal run
            run = False

            if child_process is None:
                return

            child_process.join(Worker.SIGTERM_TIMEOUT)
            if child_process.is_alive():
                raise Worker.TimeoutError(Worker.SIGTERM_TIMEOUT)

        signal.signal(signal.SIGTERM, _handle_sigterm)

        while run:
            try:
                # We must have some non-infinite delay here to avoid blocking even after _handle_sigterm is called
                task = self._in_queue.get(block=True, timeout=config.backend.block_delay)
            except queue.Empty:
                continue

            entry = {}
            try:
                self._is_working.value = 1
                logging.debug(f'{self}: Begin {self._plugin.metadata.name} analysis on {task.scheduler_state.uid}')
                start_time = time.time()

                child_process = mp.Process(
                    target=self._child_entrypoint,
                    args=(self._plugin, task, send_conn),
                )
                child_process.start()
                child_process.join(timeout=self._worker_config.timeout)
                if not recv_conn.poll():
                    raise Worker.TimeoutError(self._worker_config.timeout)

                result = recv_conn.recv()

                if isinstance(result, Exception):
                    raise result

                duration = time.time() - start_time

                entry['analysis'] = result
                logging.debug(f'{self}: Finished {self._plugin.metadata.name} analysis on {task.scheduler_state.uid}')
                if duration > 120:
                    logging.info(
                        f'Analysis {self._plugin.metadata.name} on {task.scheduler_state.uid} is slow: took {duration:.1f} seconds'
                    )
                self._update_duration_stats(duration)
            except Worker.TimeoutError as err:
                logging.warning(f'{self} timed out after {err.timeout} seconds.')
                entry['timeout'] = (self._plugin.metadata.name, 'Analysis timed out')
            except Exception as exc:  # pylint: disable=broad-except
                # As tracebacks can't be pickled we just print the __exception_str__ that we set in the child
                logging.error(f'{self} got a exception during analysis:\n {exc}', exc_info=False)
                logging.error(exc.__exception_str__)
                entry['exception'] = (self._plugin.metadata.name, 'Analysis threw an exception')
            finally:
                # Don't kill another process if it uses the same PID as our dead worker
                if child_process.is_alive():
                    child = psutil.Process(pid=child_process.pid)
                    for grandchild in child.children(recursive=True):
                        grandchild.kill()
                    child.kill()
                self._is_working.value = 0

            self._out_queue.put((task.scheduler_state, entry))

    def write_result_in_file_object(self, entry: tuple, file_object: FileObject):
        """Takes a file_object and an entry as it is returned by :py:func:`run`
        and returns a FileObject with the corresponding fileds set.
        """
        if 'analysis' in entry:
            file_object.processed_analysis[self._plugin.metadata.name] = entry['analysis']
        elif 'timeout' in entry:
            file_object.analysis_exception = entry['timeout']
        elif 'exception' in entry:
            file_object.analysis_exception = entry['exception']

    @staticmethod
    def _child_entrypoint(plugin: analysis.PluginV0, task: PluginRunner.Task, conn: mp.connection.Connection):
        """Processes a single task then returns.
        The result is written to ``conn``.
        Exceptions and formatted tracebacks are also written to ``conn``.
        """
        try:
            result = plugin.get_analysis(io.FileIO(task.path), task.virtual_file_path, task.dependencies)
        except Exception as exc:  # pylint: disable=broad-except
            result = exc
            result.__exception_str__ = traceback.format_exc()

        conn.send(result)

    def _update_duration_stats(self, duration):
        with self._stats.get_lock():
            self._stats[self._stats_idx.value] = duration
        self._stats_idx.value += 1
        if self._stats_idx.value >= ANALYSIS_STATS_LIMIT:
            # if the stats array is full, overwrite the oldest result
            self._stats_idx.value = 0
        if self._stats_count.value < ANALYSIS_STATS_LIMIT:
            self._stats_count.value += 1

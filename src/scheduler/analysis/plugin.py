from __future__ import annotations

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
from pydantic import BaseModel, ConfigDict

import config
from objects.file import FileObject  # noqa: TCH001  # needed by pydantic
from statistic.analysis_stats import ANALYSIS_STATS_LIMIT
from storage.file_service import FileService

if typing.TYPE_CHECKING:
    from analysis.plugin import AnalysisPluginV0


class PluginRunner:
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
        model_config = ConfigDict(arbitrary_types_allowed=True)

    def __init__(
        self,
        plugin: AnalysisPluginV0,
        config: Config,
        schemata: typing.Dict[str, pydantic.BaseModel],
    ):
        self._plugin = plugin
        self._config = config
        self._schemata = schemata

        self._in_queue: mp.Queue = mp.Queue()
        #: Workers put the ``Task.scheduler_state`` and the finished analysis in the out_queue
        self.out_queue: mp.Queue = mp.Queue()

        self.stats = mp.Array(ctypes.c_float, ANALYSIS_STATS_LIMIT)
        self.stats_count = mp.Value('i', 0)
        self._stats_idx = mp.Value('i', 0)

        self._file_service = FileService()

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
        return sum([worker.is_working() for worker in self._workers])

    def start(self):
        for worker in self._workers:
            worker.start()

    def shutdown(self):
        for worker in self._workers:
            if worker.is_alive():
                worker.terminate()

    def queue_analysis(self, file_object: FileObject):
        """Queues the analysis of ``file_object`` with ``self._plugin``.
        The caller of this method has to ensure that the dependencies are fulfilled.
        """
        dependencies = {}
        for dependency in self._plugin.metadata.dependencies:
            Schema = self._schemata[dependency]  # noqa: N806
            # Try to convert to the schema defined by the plugin
            result = file_object.processed_analysis[dependency]['result']
            dependencies[dependency] = Schema(**result)
        # also allow plugins to access unpacking results (which cannot be defined as dependency and have no schema)
        dependencies['unpacker'] = file_object.processed_analysis.get('unpacker', {}).get('result')

        logging.debug(f'Queueing analysis for {file_object.uid}')
        self._in_queue.put(
            PluginRunner.Task(
                virtual_file_path=file_object.virtual_file_path,
                path=self._file_service.generate_path(file_object),
                dependencies=dependencies,
                scheduler_state=file_object,
            )
        )


class Worker(mp.Process):
    """A process that executes a plugin in a child process."""

    # The amount of time in seconds that a worker has to complete when it shall terminate.
    # We cannot rely on the plugins timeout as this might be too large.
    SIGTERM_TIMEOUT = 5

    class TimeoutError(Exception):  # noqa: A001
        def __init__(self, timeout: float):
            self.timeout = timeout

    class CrashedError(Exception):
        pass

    class Config(BaseModel):
        """A class containing all parameters of the worker"""

        #: Timeout in seconds after which the analysis is aborted
        timeout: int

    def __init__(  # noqa: PLR0913
        self,
        plugin: AnalysisPluginV0,
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
        self._out_queue = out_queue

        self._stats = stats
        self._stats_count = stats_count
        self._stats_idx = stats_idx

        # Used for statistics
        self._is_working = mp.Value('i')
        self._is_working.value = 0

    def is_working(self):
        return self._is_working.value != 0

    def run(self):  # noqa: C901, PLR0912, PLR0915
        run = True
        result = None
        recv_conn, send_conn = mp.Pipe(duplex=False)

        child_process = None

        def _handle_sigterm(signum, frame):
            del signum, frame
            logging.info(f'{self} received SIGTERM. Shutting down.')
            nonlocal run
            nonlocal result
            run = False

            if child_process is None:
                return

            if not child_process.is_alive():
                return

            if not recv_conn.poll(Worker.SIGTERM_TIMEOUT):
                raise Worker.TimeoutError(Worker.SIGTERM_TIMEOUT)

            result = recv_conn.recv()

        signal.signal(signal.SIGTERM, _handle_sigterm)

        while run:
            try:
                # We must have some non-infinite delay here to avoid blocking even after _handle_sigterm is called
                task = self._in_queue.get(block=True, timeout=config.backend.block_delay)
            except queue.Empty:
                continue

            analysis_description = f'{self._plugin.metadata.name} analysis on {task.scheduler_state.uid}'

            entry = {}
            try:
                self._is_working.value = 1
                logging.debug(f'{self}: Beginning {analysis_description}')
                start_time = time.time()

                child_process = mp.Process(
                    target=self._child_entrypoint,
                    args=(self._plugin, task, send_conn),
                )
                child_process.start()
                # If process crashes without an exception (e.g. SEGFAULT) we will report a timeout
                if not recv_conn.poll(self._worker_config.timeout):
                    raise Worker.TimeoutError(self._worker_config.timeout)

                result = recv_conn.recv()

                if isinstance(result, str):
                    raise AnalysisExceptionError(result)

                duration = time.time() - start_time

                entry['analysis'] = result
                logging.debug(f'{self}: Finished {analysis_description}')
                if duration > 120:  # noqa: PLR2004
                    logging.info(f'{analysis_description} is slow: took {duration:.1f} seconds')
                self._update_duration_stats(duration)
            except Worker.TimeoutError as err:
                logging.warning(f'{analysis_description} timed out after {err.timeout} seconds.')
                entry['timeout'] = (self._plugin.metadata.name, 'Analysis timed out')
            except Worker.CrashedError:
                logging.warning(f'{analysis_description} crashed.')
                entry['exception'] = (self._plugin.metadata.name, 'Analysis crashed')
            except AnalysisExceptionError as exc:
                logging.error(f'{self} got an exception during {analysis_description}: {exc}')
                entry['exception'] = (self._plugin.metadata.name, 'Exception occurred during analysis')
            except Exception as error:
                logging.exception(f'An unexpected exception occurred during {analysis_description}: {error}')
                entry['exception'] = (self._plugin.metadata.name, 'An unexpected exception occurred')
            finally:
                # Don't kill another process if it uses the same PID as our dead worker
                if child_process.is_alive():
                    child = psutil.Process(pid=child_process.pid)
                    for grandchild in child.children(recursive=True):
                        grandchild.kill()
                    child.kill()
                self._is_working.value = 0

            fw = task.scheduler_state
            self._write_result_in_file_object(entry, fw)
            self._out_queue.put(fw)

    def _write_result_in_file_object(self, entry: dict, file_object: FileObject):
        """Takes a file_object and an entry as it is returned by :py:func:`Worker.run`
        and returns a FileObject with the corresponding fileds set.
        """
        if 'analysis' in entry:
            file_object.processed_analysis[self._plugin.metadata.name] = entry['analysis']
        elif 'timeout' in entry:
            file_object.analysis_exception = entry['timeout']
        elif 'exception' in entry:
            file_object.analysis_exception = entry['exception']

    @staticmethod
    def _child_entrypoint(plugin: AnalysisPluginV0, task: PluginRunner.Task, conn: mp.connection.Connection):
        """Processes a single task then returns.
        The result is written to ``conn``.
        Exceptions and formatted tracebacks are also written to ``conn``.
        """
        try:
            result = plugin.get_analysis(io.FileIO(task.path), task.virtual_file_path, task.dependencies)
        except Exception as exc:
            result = f'{exc}: {traceback.format_exc()}'

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


class AnalysisExceptionError(Exception):
    pass

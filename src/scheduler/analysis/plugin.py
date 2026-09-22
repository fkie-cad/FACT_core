from __future__ import annotations
import os

import ctypes
import io
import logging
import multiprocessing as mp
import multiprocessing.connection
import queue
import signal
import threading
import time
import traceback
from pathlib import Path  # noqa: TC003  # needed by pydantic
from typing import TYPE_CHECKING

import psutil
import pydantic
from pydantic import BaseModel, ConfigDict

import config
from analysis.plugin.plugin import AnalysisFailedError
from objects.file import FileObject  # noqa: TC001 # needed by pydantic
from statistic.analysis_stats import ANALYSIS_STATS_LIMIT
from storage.file_service import FileService

if TYPE_CHECKING:
    from types import FrameType

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
        virtual_file_path: dict
        #: The path of the file on the disk
        path: Path
        #: A dictionary containing plugin names as keys and their analysis as value.
        dependencies: dict
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
        schemata: dict[str, type[pydantic.BaseModel]],
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
        # guards the ``_workers`` list against concurrent grow/shrink operations
        self._worker_lock = threading.Lock()

        worker_config = Worker.Config(
            timeout=self._config.timeout,
        )
        self._workers = [self._create_worker(worker_config, idx) for idx, _ in enumerate(range(self._config.process_count))]

    def _create_worker(self, worker_config: Worker.Config, idx: int) -> Worker:
        return Worker(
            plugin=self._plugin,
            worker_config=worker_config,
            in_queue=self._in_queue,
            out_queue=self.out_queue,
            stats=self.stats,
            stats_count=self.stats_count,
            stats_idx=self._stats_idx,
            name=f'{self._plugin.metadata.name} worker {idx}',
        )

    def update_worker_count(self, new_count: int) -> None:
        """Adjust the number of worker processes for ``self._plugin``.

        Growing starts new workers. Shrinking signals the excess workers to terminate
        cleanly — each finishes any in-flight analysis before exiting, so no results are
        lost — and waits for them to exit.

        This must be called from the process that owns ``self._workers`` (the backend main
        process), since the worker list is not shared with forked child processes.
        """
        with self._worker_lock:
            current = len(self._workers)
            if new_count == current:
                return
            if new_count > current:
                worker_config = Worker.Config(timeout=self._config.timeout)
                additional_workers = new_count - current
                logging.warning(f'[{self._plugin.metadata.name}]: starting {additional_workers} additional workers')
                for idx in range(additional_workers):
                    worker = self._create_worker(worker_config, current + idx)
                    worker.start()
                    self._workers.append(worker)
                return
            # shrink: ask the excess workers to finish their current analysis and exit
            removed = self._workers[new_count:]
            self._workers = self._workers[:new_count]
            workers_to_remove = current - new_count
            logging.warning(f'[{self._plugin.metadata.name}]: stopping {workers_to_remove} workers')
            for worker in removed:
                if worker.is_alive():
                    worker.terminate()
                    # wait for the worker to finish its in-flight analysis and exit (results preserved)
                    worker.join(timeout=Worker.SIGTERM_TIMEOUT + 1)

    def get_queue_len(self) -> int:
        return self._in_queue.qsize()

    def get_active_worker_count(self) -> int:
        """Returns the amount of workers that currently analyze a file"""
        return sum([worker.is_working() for worker in self._workers])

    def start(self) -> None:
        for worker in self._workers:
            worker.start()

    def shutdown(self) -> None:
        for worker in self._workers:
            if worker.is_alive():
                worker.terminate()

    def queue_analysis(self, file_object: FileObject) -> None:
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
                path=self._file_service.generate_path_from_uid(file_object.uid),
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

    def __init__(
        self,
        plugin: AnalysisPluginV0,
        worker_config: Config,
        in_queue: mp.Queue,
        out_queue: mp.Queue,
        stats: mp.Array,
        stats_count: mp.Value,
        stats_idx: mp.Value,
        name: str,
    ):
        super().__init__(name=name)
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

        self.name = name

    def is_working(self) -> bool:
        return self._is_working.value != 0

    def run(self) -> None:  # noqa: C901, PLR0912, PLR0915
        run = True
        result = None
        recv_conn, send_conn = mp.Pipe(duplex=False)

        child_process = None

        def _handle_sigterm(signum: int, frame: FrameType | None) -> None:
            del signum, frame
            logging.warning(f'{self.name} received SIGTERM. Shutting down.')
            # Only tell the run loop to stop. Do NOT read ``recv_conn`` or raise here: the
            # main loop also reads ``recv_conn``, so consuming the in-flight result inside
            # this handler would corrupt that read (the worker would either block forever
            # on the now-empty pipe or silently drop the result). Leaving the receive to
            # the run loop lets the worker finish its current analysis, put it on the
            # out_queue and only then exit, so in-flight results are preserved on a clean
            # shutdown/shrink instead of being lost.
            nonlocal run
            run = False

        signal.signal(signal.SIGTERM, _handle_sigterm)

        while run:
            try:
                # We must have some non-infinite delay here to avoid blocking even after _handle_sigterm is called
                task = self._in_queue.get(block=True, timeout=config.backend.block_delay)
            except queue.Empty:
                continue

            analysis_description = f'{self.name} analysis on {task.scheduler_state.uid}'

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
                    raise self.TimeoutError(self._worker_config.timeout)

                result = recv_conn.recv()

                if isinstance(result, str):
                    if result.startswith('Analysis failed'):
                        raise AnalysisFailedError(result)
                    raise AnalysisExceptionError(result)

                duration = time.time() - start_time

                entry['analysis'] = result
                logging.debug(f'{self}: Finished {analysis_description}')
                if duration > 120:  # noqa: PLR2004
                    logging.info(f'{analysis_description} is slow: took {duration:.1f} seconds')
                self._update_duration_stats(duration)
            except self.TimeoutError as err:
                logging.warning(f'{analysis_description} timed out after {err.timeout} seconds.')
                entry['timeout'] = (self._plugin.metadata.name, 'Analysis timed out')
            except self.CrashedError:
                logging.warning(f'{analysis_description} crashed.')
                entry['exception'] = (self._plugin.metadata.name, 'Analysis crashed')
            except AnalysisFailedError as exc:
                entry['exception'] = (self._plugin.metadata.name, str(exc))
            except AnalysisExceptionError as exc:
                logging.error(f'{self} got an exception during {analysis_description}: {exc}')
                entry['exception'] = (self._plugin.metadata.name, 'Exception occurred during analysis')
            except Exception as error:
                logging.exception(f'An unexpected exception occurred during {analysis_description}: {error}')
                entry['exception'] = (self._plugin.metadata.name, 'An unexpected exception occurred')
            finally:
                # Don't kill another process if it uses the same PID as our dead worker
                child_process.join(timeout=5)
                if child_process.is_alive():
                    child = psutil.Process(pid=child_process.pid)
                    for grandchild in child.children(recursive=True):
                        grandchild.kill()
                    child.kill()
                self._is_working.value = 0

            fw = task.scheduler_state
            self._write_result_in_file_object(entry, fw)
            self._out_queue.put(fw)
            del fw, task, result, entry
            result = None

        logging.warning(f'{self.name} stopped')

    def _write_result_in_file_object(self, entry: dict, file_object: FileObject) -> None:
        """Takes a file_object and an entry as it is returned by :py:func:`Worker.run`
        and returns a FileObject with the corresponding fields set.
        """
        if 'analysis' in entry:
            file_object.processed_analysis[self._plugin.metadata.name] = entry['analysis']
        elif 'timeout' in entry:
            file_object.analysis_exception = entry['timeout']
        elif 'exception' in entry:
            file_object.analysis_exception = entry['exception']

    @staticmethod
    def _child_entrypoint(plugin: AnalysisPluginV0, task: PluginRunner.Task, conn: mp.connection.Connection) -> None:
        """Processes a single task then returns.
        The result is written to ``conn``.
        Exceptions and formatted tracebacks are also written to ``conn``.
        """
        try:
            result = plugin.get_analysis(io.FileIO(str(task.path)), task.virtual_file_path, task.dependencies)
        except AnalysisFailedError as exc:
            result = f'Analysis failed: {exc}'
        except Exception as exc:
            result = f'{exc}: {traceback.format_exc()}'

        conn.send(result)

    def _update_duration_stats(self, duration: float) -> None:
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

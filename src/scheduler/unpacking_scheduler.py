from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from multiprocessing import Manager, Queue, Value
from queue import Empty
from tempfile import TemporaryDirectory
from threading import Thread
from time import sleep

from docker.errors import DockerException

import config
from helperFunctions.logging import TerminalColors, color_string
from helperFunctions.process import (
    ExceptionSafeProcess,
    check_worker_exceptions,
    new_worker_was_started,
    stop_processes,
)
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_backend import BackendDbInterface
from unpacker.extraction_container import ExtractionContainer
from unpacker.unpack import Unpacker
from unpacker.unpack_base import ExtractionError


class NoFreeWorker(RuntimeError):
    pass


THROTTLE_INTERVAL = 2


class UnpackingScheduler:  # pylint: disable=too-many-instance-attributes
    '''
    This scheduler performs unpacking on firmware objects
    '''

    def __init__(
        self,
        post_unpack=None,
        analysis_workload=None,
        fs_organizer=None,
        unpacking_locks=None,
        db_interface=BackendDbInterface,
    ):
        self.stop_condition = Value('i', 0)
        self.throttle_condition = Value('i', 0)
        self.get_analysis_workload = analysis_workload
        self.in_queue = Queue()
        self.work_load_counter = 25
        self.manager = Manager()
        self.workers = self.manager.list()  # type: list[ExtractionContainer]
        self.currently_extracted = self.manager.dict()  # type: dict[str, dict[str, set]]
        self.worker_tmp_dirs = []  # type: list[TemporaryDirectory]
        self.sync_lock = self.manager.Lock()
        self.pending_tasks: dict[int, Thread] = {}
        self.post_unpack = post_unpack
        self.unpacking_locks = unpacking_locks
        self.unpacker = Unpacker(fs_organizer=fs_organizer, unpacking_locks=unpacking_locks)
        self.work_load_process = None
        self.extraction_process = None
        self.db_interface = db_interface

    @contextmanager
    def _sync(self):
        try:
            self.sync_lock.acquire()
            yield
        finally:
            self.sync_lock.release()

    def start(self):
        self.create_containers()
        self.work_load_process = self.start_work_load_monitor()
        self.extraction_process = self._start_extraction_loop()
        logging.info('Unpacking scheduler online')

    def _start_extraction_loop(self):
        logging.debug('Starting extraction loop')
        extraction_loop_process = ExceptionSafeProcess(target=self.extraction_loop)
        extraction_loop_process.start()
        return extraction_loop_process

    def shutdown(self):
        '''
        shutdown the scheduler
        '''
        logging.debug('Shutting down unpacking scheduler ...')
        self.stop_condition.value = 1
        self.in_queue.close()
        stop_processes(
            [self.work_load_process, self.extraction_process],
            10,  # give containers enough time to shut down
        )
        self.stop_containers()
        self._clean_tmp_dirs()
        self.manager.shutdown()
        logging.info('Unpacker Module offline')

    def _clean_tmp_dirs(self):
        for tmp_dir in self.worker_tmp_dirs:
            try:
                tmp_dir.cleanup()
            except PermissionError:
                logging.exception(f'Worker directory "{tmp_dir.name}" could not be cleaned')

    # ---- internal functions ----

    def add_task(self, fw: Firmware):
        '''
        schedule a firmware_object for unpacking
        '''
        fw.root_uid = fw.uid  # make sure the root_uid is set correctly for unpacking and analysis scheduling
        self.in_queue.put(fw)

    def get_scheduled_workload(self):
        return {'unpacking_queue': self.in_queue.qsize(), 'is_throttled': self.throttle_condition.value == 1}

    def create_containers(self):
        for id_ in range(config.backend.unpacking.processes):
            tmp_dir = TemporaryDirectory(  # pylint: disable=consider-using-with
                dir=config.backend.docker_mount_base_dir
            )
            container = ExtractionContainer(id_=id_, tmp_dir=tmp_dir, value=self.manager.Value('i', 0))
            container.start()
            self.workers.append(container)
            self.worker_tmp_dirs.append(tmp_dir)

    def stop_containers(self):
        with ThreadPoolExecutor(max_workers=len(self.workers)) as pool:
            pool.map(lambda container: container.stop(), self.workers)

    def extraction_loop(self):
        while self.stop_condition.value == 0:
            self.check_pending()
            try:
                container = self.get_free_worker()
                task = self.in_queue.get(timeout=1)
                task_thread = Thread(
                    target=self._work_thread_wrapper,
                    kwargs=dict(task=task, container=container),
                )
                task_thread.start()
                logging.debug(f'Started Worker on {task.uid} ({container.tmp_dir})')
                self.pending_tasks[container.id_] = task_thread
            except NoFreeWorker:
                logging.debug('No free worker. Sleeping ..')
                sleep(0.2)
            except Empty:
                pass

    def check_pending(self):
        for container_id, thread in list(self.pending_tasks.items()):
            if not thread.is_alive():
                thread.join()
                container = self.workers[container_id]
                if container.exception_occurred():
                    container.restart()
                    self.workers[container_id] = container  # force update of manager
                self.pending_tasks.pop(container_id)

    def get_free_worker(self) -> ExtractionContainer:
        for container in self.workers:
            if container.id_ not in self.pending_tasks:
                return container
        raise NoFreeWorker()

    def _work_thread_wrapper(self, task: FileObject, container: ExtractionContainer):
        """
        Exceptions in Threads will simply disappear when the thread is joined. We wrap everything in a
        try-except block and log exceptions so that no exception occurs unnoticed.
        """
        try:
            self.work_thread(task, container)
        except Exception:
            logging.exception(f'Exception occurred during unpacking of {task.uid}')

    def work_thread(self, task: FileObject, container: ExtractionContainer):
        if isinstance(task, Firmware):
            self._init_currently_unpacked(task)

        with TemporaryDirectory(dir=container.tmp_dir.name) as tmp_dir:
            try:
                extracted_objects = self.unpacker.unpack(task, tmp_dir, container)
            except ExtractionError:
                docker_logs = self._fetch_logs(container)
                logging.warning(f'Exception happened during extraction of {task.uid}.{docker_logs}')
                container.set_exception()
                extracted_objects = []

            sleep(config.backend.unpacking.delay)  # unpacking may be too fast for the FS to keep up

            # each worker needs its own interface because connections are not thread-safe
            db_interface = self.db_interface()
            db_interface.add_object(task)  # save FO before submitting to analysis scheduler
            self.post_unpack(task)
            self._update_currently_unpacked(task, extracted_objects, db_interface)
            self._schedule_extracted_files(extracted_objects)

    def _update_currently_unpacked(
        self, task: FileObject, extracted_objects: list[FileObject], db_interface: BackendDbInterface
    ):
        with self._sync():
            currently_unpacked = self.currently_extracted[task.root_uid]
            currently_unpacked['done'].add(task.uid)
            for fo in extracted_objects[:]:
                if fo.uid not in currently_unpacked['done']:
                    currently_unpacked['remaining'].add(fo.uid)
                else:
                    # FO was already unpacked from this FW -> only update VFP and skip unpacking/analysis
                    extracted_objects.remove(fo)
                    db_interface.add_vfp(task.uid, fo.uid, fo.virtual_file_path[task.uid])
                    logging.debug(f'Skipping unpacking/analysis of {fo.uid} (part of {fo.root_uid}).')
            currently_unpacked['remaining'].remove(task.uid)
            self.currently_extracted[task.root_uid] = currently_unpacked  # overwrite object to trigger update
            if not currently_unpacked['remaining']:
                logging.info(f'Unpacking of firmware {task.root_uid} completed.')

    @staticmethod
    def _fetch_logs(container: ExtractionContainer) -> str:
        try:
            return f'\n===Container Logs Start===\n{container.get_logs()}\n===Container Logs End==='
        except DockerException:
            logging.error('Could not fetch unpacking container logs')
            return ''

    def _schedule_extracted_files(self, object_list: list[FileObject]):
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
        work_load_process = ExceptionSafeProcess(target=self._work_load_monitor)
        work_load_process.start()
        return work_load_process

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
            message = f'Queue Length (Analysis/Unpack): {workload} / {unpack_queue_size}'
            log_function(color_string(message, TerminalColors.WARNING))

            if workload < config.backend.unpacking.throttle_limit:
                self.throttle_condition.value = 0
            else:
                self.throttle_condition.value = 1
            sleep(THROTTLE_INTERVAL)

    def _get_combined_analysis_workload(self):
        if self.get_analysis_workload is not None:
            return self.get_analysis_workload()
        return 0

    def check_exceptions(self):
        list_with_load_process = [self.work_load_process]
        shutdown = check_worker_exceptions(list_with_load_process, 'unpack-load', self._work_load_monitor)
        if new_worker_was_started(new_process=list_with_load_process[0], old_process=self.work_load_process):
            self.work_load_process = list_with_load_process.pop()
        return shutdown

    def _init_currently_unpacked(self, fo: Firmware):
        with self._sync():
            if fo.uid in self.currently_extracted:
                logging.warning(f'starting unpacking of {fo.uid} but it is currently also still being unpacked')
            else:
                self.currently_extracted[fo.uid] = {'remaining': {fo.uid}, 'done': set()}

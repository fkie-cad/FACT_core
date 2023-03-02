from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Queue, Value
from pathlib import Path
from queue import Empty
from tempfile import TemporaryDirectory
from threading import Thread
from time import sleep

from docker.errors import DockerException

from config import cfg
from helperFunctions.logging import TerminalColors, color_string
from helperFunctions.process import (
    ExceptionSafeProcess,
    check_worker_exceptions,
    new_worker_was_started,
    stop_processes,
)
from objects.file import FileObject
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

    def __init__(self, post_unpack=None, analysis_workload=None, fs_organizer=None, unpacking_locks=None):
        self.stop_condition = Value('i', 0)
        self.throttle_condition = Value('i', 0)
        self.get_analysis_workload = analysis_workload
        self.in_queue = Queue()
        self.work_load_counter = 25
        self.workers: list[ExtractionContainer] = []
        self.pending_tasks: dict[int, Thread] = {}
        self.post_unpack = post_unpack
        self.unpacking_locks = unpacking_locks
        self.unpacker = Unpacker(fs_organizer=fs_organizer, unpacking_locks=unpacking_locks)
        self.work_load_process = None
        self.extraction_process = None

    def start(self):
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
        logging.info('Unpacker Module offline')

    # ---- internal functions ----

    def add_task(self, fo):
        '''
        schedule a firmware_object for unpacking
        '''
        self.in_queue.put(fo)

    def get_scheduled_workload(self):
        return {'unpacking_queue': self.in_queue.qsize(), 'is_throttled': self.throttle_condition.value == 1}

    def create_containers(self):
        for id_ in range(cfg.unpack.threads):
            container = ExtractionContainer(id_=id_)
            container.start()
            self.workers.append(container)

    def stop_containers(self):
        pool = ThreadPoolExecutor(max_workers=len(self.workers))
        pool.map(lambda container: container.stop(), self.workers)
        pool.shutdown(wait=True, cancel_futures=False)

    def extraction_loop(self):
        self.create_containers()
        while self.stop_condition.value == 0:
            self.check_pending()
            try:
                container = self.get_free_worker()
                task = self.in_queue.get(timeout=1)
                task_thread = Thread(
                    target=self.work_thread,
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
        self.stop_containers()

    def check_pending(self):
        for container_id, thread in list(self.pending_tasks.items()):
            if not thread.is_alive():
                thread.join()
                container = self.workers[container_id]
                if container.exception_happened():
                    container.restart()
                self.pending_tasks.pop(container_id)

    def get_free_worker(self) -> ExtractionContainer:
        for container in self.workers:
            if container.id_ not in self.pending_tasks:
                return container
        raise NoFreeWorker()

    def work_thread(self, task: FileObject, container: ExtractionContainer):
        with TemporaryDirectory(dir=container.tmp_dir.name) as tmp_dir:
            container_url = f'http://localhost:{container.port}/start/{Path(tmp_dir).name}'

            extracted_objects = None
            try:
                extracted_objects = self.unpacker.unpack(task, tmp_dir, container_url)
            except ExtractionError:
                docker_logs = self._fetch_logs(container)
                logging.warning(f'Exception happened during extraction of {task.uid}.{docker_logs}')
                container.exception = True

            sleep(cfg.expert_settings.unpacking_delay)  # unpacking may be too fast for the FS to keep up

            self.post_unpack(task)
            if extracted_objects:
                self.schedule_extracted_files(extracted_objects)

    @staticmethod
    def _fetch_logs(container) -> str:
        try:
            return f'\n===Container Logs Start===\n{container.container.logs().decode()}\n===Container Logs End==='
        except DockerException:
            logging.error('Could not fetch unpacking container logs')
            return ''

    def schedule_extracted_files(self, object_list: list[FileObject]):
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

            if workload < cfg.expert_settings.unpack_throttle_limit:
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

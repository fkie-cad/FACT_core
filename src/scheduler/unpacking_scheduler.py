from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from multiprocessing import Queue, Value
from pathlib import Path
from queue import Empty
from tempfile import TemporaryDirectory
from threading import Thread
from time import sleep

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


class UnpackingScheduler:  # pylint: disable=too-many-instance-attributes
    '''
    This scheduler performs unpacking on firmware objects
    '''

    def __init__(self, config=None, post_unpack=None, analysis_workload=None, unpacking_locks=None):
        self.config = config
        self.stop_condition = Value('i', 0)
        self.get_analysis_workload = analysis_workload
        self.in_queue = Queue()
        self.work_load_counter = 25
        self.workers: list[ExtractionContainer] = []
        self.pending_tasks: dict[int, Thread] = {}
        self.post_unpack = post_unpack
        self.unpacking_locks = unpacking_locks
        self.create_containers()
        self.unpacker = Unpacker(config=self.config, unpacking_locks=self.unpacking_locks)
        self.work_load_process = self.start_work_load_monitor()
        self.extraction_process = self._start_extraction_loop()
        logging.info('Unpacking scheduler online')

    def _start_extraction_loop(self):
        logging.debug('Starting extraction loop')
        extraction_loop_process = ExceptionSafeProcess(target=self.extraction_loop)
        extraction_loop_process.start()
        return extraction_loop_process

    def add_task(self, fo):
        '''
        schedule a firmware_object for unpacking
        '''
        self.in_queue.put(fo)

    def get_scheduled_workload(self):
        return {'unpacking_queue': self.in_queue.qsize()}

    def shutdown(self):
        '''
        shutdown the scheduler
        '''
        logging.debug('Shutting down...')
        self.stop_condition.value = 1
        stop_processes([self.work_load_process, self.extraction_process])
        self.stop_containers()
        self.in_queue.close()
        logging.info('Unpacking scheduler offline')

    # ---- internal functions ----

    def create_containers(self):
        for id_ in range(self.config.getint('unpack', 'threads')):
            container = ExtractionContainer(self.config, id_=id_)
            container.start()
            self.workers.append(container)

    def stop_containers(self):
        pool = ThreadPoolExecutor(max_workers=len(self.workers))
        pool.map(lambda container: container.stop(), self.workers)
        pool.shutdown(wait=True, cancel_futures=False)

    def extraction_loop(self):
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
                extracted_objects = self.unpacker.unpack(task, container_url, tmp_dir)
            except ExtractionError:
                logging.warning(f'Exception happened during extraction of {task.uid}')
                container.exception = True

            # FixMe? sleep(0.1)  # This stuff is too fast for the FS to keep up ...

            self.post_unpack(task)
            if extracted_objects:
                self.schedule_extracted_files(extracted_objects)

    def schedule_extracted_files(self, object_list: list[FileObject]):
        for item in object_list:
            self.in_queue.put(item)

    def start_work_load_monitor(self):
        logging.debug('Start work load monitor...')
        work_load_process = ExceptionSafeProcess(target=self._work_load_monitor)
        work_load_process.start()
        return work_load_process

    def _work_load_monitor(self):
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

            sleep(2)

    def _get_combined_analysis_workload(self):
        if self.get_analysis_workload is not None:
            return self.get_analysis_workload()
        return 0

    def check_exceptions(self):
        list_with_load_process = [self.work_load_process]
        shutdown = check_worker_exceptions(list_with_load_process, 'unpack-load', self.config, self._work_load_monitor)
        if new_worker_was_started(new_process=list_with_load_process[0], old_process=self.work_load_process):
            self.work_load_process = list_with_load_process.pop()

        return shutdown

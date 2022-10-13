import logging
from multiprocessing import Queue, Value
from os import getgid, getuid
from pathlib import Path
from queue import Empty
from tempfile import TemporaryDirectory
from threading import Thread
from time import sleep

import docker
from docker.types import Mount

from helperFunctions.logging import TerminalColors, color_string
from helperFunctions.process import (
    ExceptionSafeProcess,
    check_worker_exceptions,
    new_worker_was_started,
    stop_processes,
)
from unpacker.unpack import Unpacker

WORKER_BASE_PORT = 9900
BASE_URL = 'http://localhost:{port}'
WORKER_COUNT = 8
TARGET_DIR = Path('.') / 'extracted_files'


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
        self.workers = []
        self.pending_tasks = []
        self.post_unpack = post_unpack
        self.unpacking_locks = unpacking_locks
        self.start_container()
        self.unpacker = Unpacker(config=self.config, unpacking_locks=self.unpacking_locks)
        self.work_load_process = self.start_work_load_monitor()
        self.extraction_process = self._start_extraction_loop()
        logging.info('Unpacker Module online')

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
        self.stop_container()
        self.in_queue.close()
        logging.info('Unpacker Module offline')

    # ---- internal functions ----

    def start_container(self):
        for _ in range(WORKER_COUNT):
            self._start_single_container()

    def stop_container(self):
        for _, tmp_dir, container in self.workers:
            logging.info('Stopping unpack worker')
            container.stop(timeout=1)
            try:
                tmp_dir.cleanup()
            except PermissionError:
                logging.error(f'Unable to delete worker folder {tmp_dir.name}', exc_info=True)

    def _start_single_container(self):
        tmp_dir = TemporaryDirectory()
        port = max(worker_port for worker_port, _, _ in self.workers) + 1 if self.workers else WORKER_BASE_PORT
        volume = Mount('/tmp/extractor', str(tmp_dir.name), read_only=False, type='bind')
        client = docker.from_env()

        container = client.containers.run(
            image='fact_extractor_local',
            ports={'5000/tcp': port},
            mem_limit='8g',
            mounts=[volume],
            volumes={'/dev': {'bind': '/dev', 'mode': 'rw'}},
            privileged=True,
            detach=True,
            command=f'--chown {getuid()}:{getgid()}',
            remove=True,
        )
        self.workers.append((port, tmp_dir, container))

    def extraction_loop(self):
        while self.stop_condition.value == 0:
            self.check_pending()
            try:
                worker_port, base_tmp_dir = self.get_free_worker()
                task = self.in_queue.get(timeout=1)
                task_thread = Thread(
                    target=self.work_thread, kwargs=dict(task=task, extraction_dir=base_tmp_dir, port=worker_port)
                )
                task_thread.start()
                logging.debug(f'Started Worker on {task.uid} ({base_tmp_dir})')
                self.pending_tasks.append((worker_port, task, task_thread))  # Check if this is sensible
            except NoFreeWorker:
                logging.debug('No free worker. Sleeping ..')
                sleep(0.2)
            except Empty:
                pass

    def check_pending(self):
        still_pending = []
        while self.pending_tasks:
            port, task, thread = self.pending_tasks.pop()
            if not thread.is_alive():
                thread.join()
            else:
                still_pending.append((port, task, thread))
        self.pending_tasks = still_pending

    def get_free_worker(self):
        for worker, tmp_dir, _ in self.workers:
            if worker not in [worker_id for worker_id, _, _ in self.pending_tasks]:
                return worker, tmp_dir.name
        raise NoFreeWorker()

    def work_thread(self, task, extraction_dir, port):
        tmp_dir = TemporaryDirectory(dir=extraction_dir)
        container_url = f'{BASE_URL.format(port=port)}/start/{Path(tmp_dir.name).name}'

        extracted_objects = self.unpacker.unpack(task, container_url, tmp_dir)

        sleep(0.1)  # This stuff is too fast for the FS to keep up ...

        self.post_unpack(task)
        self.schedule_extracted_files(extracted_objects)

        tmp_dir.cleanup()

    def schedule_extracted_files(self, object_list):
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
            log_function(
                color_string(
                    f'Queue Length (Analysis/Unpack): {workload} / {unpack_queue_size}', TerminalColors.WARNING
                )
            )

            sleep(2)

    def _get_combined_analysis_workload(self):
        if self.get_analysis_workload is not None:
            return self.get_analysis_workload()
        return 0

    def check_exceptions(self):
        list_with_load_process = [
            self.work_load_process,
        ]
        shutdown = check_worker_exceptions(list_with_load_process, 'unpack-load', self.config, self._work_load_monitor)
        if new_worker_was_started(new_process=list_with_load_process[0], old_process=self.work_load_process):
            self.work_load_process = list_with_load_process.pop()

        return shutdown

from __future__ import annotations

import difflib
import logging
import os
from collections.abc import Callable
from multiprocessing import Process, Value
from pathlib import Path
from time import sleep

import config
from helperFunctions.process import stop_processes
from helperFunctions.yara_binary_search import YaraBinarySearchScanner
from intercom.common_redis_binding import InterComListener, InterComListenerAndResponder, InterComRedisInterface
from objects.firmware import Firmware
from storage.binary_service import BinaryService
from storage.db_interface_common import DbInterfaceCommon
from storage.fsorganizer import FSOrganizer
from storage.unpacking_locks import UnpackingLockManager


class InterComBackEndBinding:  # pylint: disable=too-many-instance-attributes
    '''
    Internal Communication Backend Binding
    '''

    def __init__(
        self,
        analysis_service=None,
        compare_service=None,
        unpacking_service=None,
        unpacking_locks=None,
        testing=False,
    ):
        self.analysis_service = analysis_service
        self.compare_service = compare_service
        self.unpacking_service = unpacking_service
        self.unpacking_locks = unpacking_locks
        self.poll_delay = config.backend.intercom_poll_delay

        self.stop_condition = Value('i', 0)
        self.process_list = []

    def start(self):
        InterComBackEndAnalysisPlugInsPublisher(analysis_service=self.analysis_service)
        self._start_listener(InterComBackEndAnalysisTask, self.unpacking_service.add_task)
        self._start_listener(InterComBackEndReAnalyzeTask, self.unpacking_service.add_task)
        self._start_listener(InterComBackEndCompareTask, self.compare_service.add_task)
        self._start_listener(InterComBackEndRawDownloadTask)
        self._start_listener(InterComBackEndFileDiffTask)
        self._start_listener(InterComBackEndTarRepackTask)
        self._start_listener(InterComBackEndBinarySearchTask)
        self._start_listener(InterComBackEndUpdateTask, self.analysis_service.update_analysis_of_object_and_children)

        self._start_listener(
            InterComBackEndDeleteFile,
            unpacking_locks=self.unpacking_locks,
            db_interface=DbInterfaceCommon(),
        )
        self._start_listener(InterComBackEndSingleFileTask, self.analysis_service.update_analysis_of_single_object)
        self._start_listener(InterComBackEndPeekBinaryTask)
        self._start_listener(InterComBackEndLogsTask)
        logging.info('Intercom online')

    def shutdown(self):
        self.stop_condition.value = 1
        stop_processes(self.process_list, config.backend.intercom_poll_delay + 1)
        logging.info('Intercom offline')

    def _start_listener(self, listener: type[InterComListener], do_after_function: Callable | None = None, **kwargs):
        process = Process(target=self._backend_worker, args=(listener, do_after_function, kwargs))
        process.start()
        self.process_list.append(process)

    def _backend_worker(self, listener: type[InterComListener], do_after_function: Callable | None, additional_args):
        interface = listener(**additional_args)
        logging.debug(f'{listener.__name__} listener started (pid={os.getpid()})')
        while self.stop_condition.value == 0:
            task = interface.get_next_task()
            if task is None:
                sleep(self.poll_delay)
            elif do_after_function is not None:
                do_after_function(task)
        logging.debug(f'{listener.__name__} listener stopped')


class InterComBackEndAnalysisPlugInsPublisher(InterComRedisInterface):
    def __init__(self, analysis_service=None):
        super().__init__()
        self.publish_available_analysis_plugins(analysis_service)

    def publish_available_analysis_plugins(self, analysis_service):
        available_plugin_dictionary = analysis_service.get_plugin_dict()
        self.redis.set('analysis_plugins', available_plugin_dictionary)


class InterComBackEndAnalysisTask(InterComListener):
    CONNECTION_TYPE = 'analysis_task'

    def __init__(self):
        super().__init__()
        self.fs_organizer = FSOrganizer()

    def post_processing(self, task, task_id):
        self.fs_organizer.store_file(task)
        return task


class InterComBackEndReAnalyzeTask(InterComListener):
    CONNECTION_TYPE = 're_analyze_task'

    def __init__(self):
        super().__init__()
        self.fs_organizer = FSOrganizer()

    def post_processing(self, task: Firmware, task_id):
        task.file_path = self.fs_organizer.generate_path(task)
        task.create_binary_from_path()
        return task


class InterComBackEndUpdateTask(InterComBackEndReAnalyzeTask):
    CONNECTION_TYPE = 'update_task'


class InterComBackEndSingleFileTask(InterComBackEndReAnalyzeTask):
    CONNECTION_TYPE = 'single_file_task'


class InterComBackEndCompareTask(InterComListener):
    CONNECTION_TYPE = 'compare_task'


class InterComBackEndRawDownloadTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'raw_download_task'
    OUTGOING_CONNECTION_TYPE = 'raw_download_task_resp'

    def __init__(self):
        super().__init__()
        self.binary_service = BinaryService()

    def get_response(self, task):
        return self.binary_service.get_binary_and_file_name(task)


class InterComBackEndFileDiffTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'file_diff_task'
    OUTGOING_CONNECTION_TYPE = 'file_diff_task_resp'

    def __init__(self):
        super().__init__()
        self.binary_service = BinaryService()

    def get_response(self, task: tuple[str, str]) -> str | None:
        uid1, uid2 = task
        content_1, name_1 = self.binary_service.get_binary_and_file_name(uid1)
        content_2, name_2 = self.binary_service.get_binary_and_file_name(uid2)
        if any(e is None for e in [content_1, content_2, name_1, name_2]):
            return None
        diff_lines = difflib.unified_diff(
            content_1.decode(errors='replace').splitlines(keepends=True),
            content_2.decode(errors='replace').splitlines(keepends=True),
            fromfile=name_1,
            tofile=name_2,
        )
        return ''.join(diff_lines)


class InterComBackEndPeekBinaryTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'binary_peek_task'
    OUTGOING_CONNECTION_TYPE = 'binary_peek_task_resp'

    def __init__(self):
        super().__init__()
        self.binary_service = BinaryService()

    def get_response(self, task: tuple[str, int, int]) -> bytes:
        return self.binary_service.read_partial_binary(*task)


class InterComBackEndTarRepackTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'tar_repack_task'
    OUTGOING_CONNECTION_TYPE = 'tar_repack_task_resp'

    def __init__(self):
        super().__init__()
        self.binary_service = BinaryService()

    def get_response(self, task):
        return self.binary_service.get_repacked_binary_and_file_name(task)


class InterComBackEndBinarySearchTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'binary_search_task'
    OUTGOING_CONNECTION_TYPE = 'binary_search_task_resp'

    def get_response(self, task):
        yara_binary_searcher = YaraBinarySearchScanner()
        uid_list = yara_binary_searcher.get_binary_search_result(task)
        return uid_list, task


class InterComBackEndDeleteFile(InterComListenerAndResponder):
    CONNECTION_TYPE = 'file_delete_task'

    def __init__(self, unpacking_locks=None, db_interface=None):
        super().__init__()
        self.fs_organizer = FSOrganizer()
        self.db = db_interface
        self.unpacking_locks: UnpackingLockManager = unpacking_locks

    def post_processing(self, task: set[str], task_id):
        # task is a set of UIDs
        uids_in_db = self.db.uid_list_exists(task)
        deleted = 0
        for uid in task:
            if self.unpacking_locks is not None and self.unpacking_locks.unpacking_lock_is_set(uid):
                logging.debug(f'File not removed, because it is processed by unpacker: {uid}')
            elif uid not in uids_in_db:
                deleted += 1
                logging.debug(f'Removing file: {uid}')
                self.fs_organizer.delete_file(uid)
            else:
                logging.warning(f'File not removed, because database entry exists: {uid}')
        if deleted:
            logging.info(f'Deleted {deleted} files')
        return task

    def get_response(self, task):
        return True  # we only want to know when the deletion is completed and not actually return something


class InterComBackEndLogsTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'logs_task'
    OUTGOING_CONNECTION_TYPE = 'logs_task_resp'

    def get_response(self, task):
        backend_logs = Path(config.backend.logging.file_backend)
        if backend_logs.is_file():
            return backend_logs.read_text().splitlines()[-100:]
        return []

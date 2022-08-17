import logging
from multiprocessing import Process, Value
from pathlib import Path
from time import sleep
from typing import Callable, Optional, Tuple, Type

from helperFunctions.process import stop_processes
from helperFunctions.program_setup import get_log_file_for_component
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
        config=None,
        analysis_service=None,
        compare_service=None,
        unpacking_service=None,
        unpacking_locks=None,
        testing=False
    ):
        self.config = config
        self.analysis_service = analysis_service
        self.compare_service = compare_service
        self.unpacking_service = unpacking_service
        self.unpacking_locks = unpacking_locks
        self.poll_delay = self.config['expert-settings'].getfloat('intercom-poll-delay')

        self.stop_condition = Value('i', 0)
        self.process_list = []
        if not testing:
            self.start_listeners()
        logging.info('InterCom started')

    def start_listeners(self):
        InterComBackEndAnalysisPlugInsPublisher(config=self.config, analysis_service=self.analysis_service)
        self._start_listener(InterComBackEndAnalysisTask, self.unpacking_service.add_task)
        self._start_listener(InterComBackEndReAnalyzeTask, self.unpacking_service.add_task)
        self._start_listener(InterComBackEndCompareTask, self.compare_service.add_task)
        self._start_listener(InterComBackEndRawDownloadTask)
        self._start_listener(InterComBackEndTarRepackTask)
        self._start_listener(InterComBackEndBinarySearchTask)
        self._start_listener(InterComBackEndUpdateTask, self.analysis_service.update_analysis_of_object_and_children)
        self._start_listener(
            InterComBackEndDeleteFile,
            unpacking_locks=self.unpacking_locks,
            db_interface=DbInterfaceCommon(config=self.config)
        )
        self._start_listener(InterComBackEndSingleFileTask, self.analysis_service.update_analysis_of_single_object)
        self._start_listener(InterComBackEndPeekBinaryTask)
        self._start_listener(InterComBackEndLogsTask)

    def shutdown(self):
        self.stop_condition.value = 1
        stop_processes(self.process_list)
        logging.warning('InterCom down')

    def _start_listener(self, listener: Type[InterComListener], do_after_function: Optional[Callable] = None, **kwargs):
        process = Process(target=self._backend_worker, args=(listener, do_after_function, kwargs))
        process.start()
        self.process_list.append(process)

    def _backend_worker(self, listener: Type[InterComListener], do_after_function: Optional[Callable], additional_args):
        interface = listener(config=self.config, **additional_args)
        logging.debug(f'{listener.__name__} listener started')
        while self.stop_condition.value == 0:
            task = interface.get_next_task()
            if task is None:
                sleep(self.poll_delay)
            elif do_after_function is not None:
                do_after_function(task)
        logging.debug(f'{listener.__name__} listener stopped')


class InterComBackEndAnalysisPlugInsPublisher(InterComRedisInterface):
    def __init__(self, config=None, analysis_service=None):
        super().__init__(config=config)
        self.publish_available_analysis_plugins(analysis_service)

    def publish_available_analysis_plugins(self, analysis_service):
        available_plugin_dictionary = analysis_service.get_plugin_dict()
        self.redis.set('analysis_plugins', available_plugin_dictionary)


class InterComBackEndAnalysisTask(InterComListener):

    CONNECTION_TYPE = 'analysis_task'

    def __init__(self, config=None):
        super().__init__(config)
        self.fs_organizer = FSOrganizer(config=config)

    def post_processing(self, task, task_id):
        self.fs_organizer.store_file(task)
        return task


class InterComBackEndReAnalyzeTask(InterComListener):

    CONNECTION_TYPE = 're_analyze_task'

    def __init__(self, config=None):
        super().__init__(config)
        self.fs_organizer = FSOrganizer(config=config)

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

    def __init__(self, config=None):
        super().__init__(config)
        self.binary_service = BinaryService(config=self.config)

    def get_response(self, task):
        return self.binary_service.get_binary_and_file_name(task)


class InterComBackEndPeekBinaryTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'binary_peek_task'
    OUTGOING_CONNECTION_TYPE = 'binary_peek_task_resp'

    def __init__(self, config=None):
        super().__init__(config)
        self.binary_service = BinaryService(config=self.config)

    def get_response(self, task: Tuple[str, int, int]) -> bytes:
        return self.binary_service.read_partial_binary(*task)


class InterComBackEndTarRepackTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'tar_repack_task'
    OUTGOING_CONNECTION_TYPE = 'tar_repack_task_resp'

    def __init__(self, config=None):
        super().__init__(config)
        self.binary_service = BinaryService(config=self.config)

    def get_response(self, task):
        return self.binary_service.get_repacked_binary_and_file_name(task)


class InterComBackEndBinarySearchTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'binary_search_task'
    OUTGOING_CONNECTION_TYPE = 'binary_search_task_resp'

    def get_response(self, task):
        yara_binary_searcher = YaraBinarySearchScanner(config=self.config)
        uid_list = yara_binary_searcher.get_binary_search_result(task)
        return uid_list, task


class InterComBackEndDeleteFile(InterComListener):

    CONNECTION_TYPE = 'file_delete_task'

    def __init__(self, config=None, unpacking_locks=None, db_interface=None):
        super().__init__(config)
        self.fs_organizer = FSOrganizer(config=config)
        self.db = db_interface
        self.unpacking_locks: UnpackingLockManager = unpacking_locks

    def post_processing(self, task, task_id):
        # task is a UID list here
        for uid in task:
            if self._entry_was_removed_from_db(uid):
                logging.info(f'removing file: {uid}')
                self.fs_organizer.delete_file(uid)
        return task

    def _entry_was_removed_from_db(self, uid: str) -> bool:
        if self.db.exists(uid):
            logging.debug(f'file not removed, because database entry exists: {uid}')
            return False
        if self.unpacking_locks is not None and self.unpacking_locks.unpacking_lock_is_set(uid):
            logging.debug(f'file not removed, because it is processed by unpacker: {uid}')
            return False
        return True


class InterComBackEndLogsTask(InterComListenerAndResponder):

    CONNECTION_TYPE = 'logs_task'
    OUTGOING_CONNECTION_TYPE = 'logs_task_resp'

    def get_response(self, task):
        backend_logs = Path(get_log_file_for_component('backend', self.config))
        if backend_logs.is_file():
            return backend_logs.read_text().splitlines()[-100:]
        return []

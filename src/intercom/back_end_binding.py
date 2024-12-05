from __future__ import annotations

import difflib
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import config
from helperFunctions.process import stop_processes
from helperFunctions.yara_binary_search import YaraBinarySearchScanner
from intercom.common_redis_binding import (
    InterComListener,
    InterComListenerAndResponder,
    publish_available_analysis_plugins,
)
from storage.binary_service import BinaryService
from storage.db_interface_common import DbInterfaceCommon
from storage.fsorganizer import FSOrganizer

if TYPE_CHECKING:
    from objects.firmware import Firmware
    from scheduler.unpacking_scheduler import UnpackingScheduler
    from storage.unpacking_locks import UnpackingLockManager


class InterComBackEndBinding:
    """
    Internal Communication Backend Binding
    """

    def __init__(
        self,
        analysis_service=None,
        compare_service=None,
        unpacking_service=None,
        unpacking_locks=None,
    ):
        self.analysis_service = analysis_service
        self.compare_service = compare_service
        self.unpacking_service: UnpackingScheduler = unpacking_service
        self.unpacking_locks = unpacking_locks
        self.listeners = [
            InterComBackEndAnalysisTask(self.unpacking_service.add_task),
            InterComBackEndReAnalyzeTask(self.unpacking_service.add_task),
            InterComBackEndCompareTask(self.compare_service.add_task),
            InterComBackEndRawDownloadTask(),
            InterComBackEndFileDiffTask(),
            InterComBackEndTarRepackTask(),
            InterComBackEndBinarySearchTask(),
            InterComBackEndUpdateTask(self.analysis_service.update_analysis_of_object_and_children),
            InterComBackEndDeleteFile(
                unpacking_locks=self.unpacking_locks,
                db_interface=DbInterfaceCommon(),
            ),
            InterComBackEndSingleFileTask(self.analysis_service.update_analysis_of_single_object),
            InterComBackEndPeekBinaryTask(),
            InterComBackEndLogsTask(),
            InterComBackEndCancelTask(self._cancel_task),
        ]

    def start(self):
        publish_available_analysis_plugins(self.analysis_service.get_plugin_dict())
        for listener in self.listeners:
            listener.start()
        logging.info('Intercom online')

    def shutdown(self):
        for listener in self.listeners:
            listener.shutdown()
        stop_processes(
            [listener.process for listener in self.listeners if listener],
            config.backend.intercom_poll_delay + 1,
        )
        logging.info('Intercom offline')

    def _cancel_task(self, root_uid: str):
        logging.warning(f'Cancelling unpacking and analysis of {root_uid}.')
        self.unpacking_service.cancel_unpacking(root_uid)
        self.analysis_service.cancel_analysis(root_uid)


class InterComBackEndAnalysisTask(InterComListener):
    CONNECTION_TYPE = 'analysis_task'

    def __init__(self, *args):
        super().__init__(*args)
        self.fs_organizer = FSOrganizer()

    def pre_process(self, task, task_id):  # noqa: ARG002
        self.fs_organizer.store_file(task)
        return task


class InterComBackEndReAnalyzeTask(InterComListener):
    CONNECTION_TYPE = 're_analyze_task'

    def __init__(self, *args):
        super().__init__(*args)
        self.fs_organizer = FSOrganizer()

    def pre_process(self, task: Firmware, task_id):  # noqa: ARG002
        task.file_path = self.fs_organizer.generate_path(task)
        task.create_binary_from_path()
        return task


class InterComBackEndUpdateTask(InterComBackEndReAnalyzeTask):
    CONNECTION_TYPE = 'update_task'


class InterComBackEndSingleFileTask(InterComBackEndReAnalyzeTask):
    CONNECTION_TYPE = 'single_file_task'


class InterComBackEndCompareTask(InterComListener):
    CONNECTION_TYPE = 'compare_task'


class InterComBackEndCancelTask(InterComListener):
    CONNECTION_TYPE = 'cancel_task'


class InterComBackEndRawDownloadTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'raw_download_task'
    OUTGOING_CONNECTION_TYPE = 'raw_download_task_resp'

    def __init__(self, *args):
        super().__init__(*args)
        self.binary_service = BinaryService()

    def get_response(self, task):
        return self.binary_service.get_binary_and_file_name(task)


class InterComBackEndFileDiffTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'file_diff_task'
    OUTGOING_CONNECTION_TYPE = 'file_diff_task_resp'

    def __init__(self, *args):
        super().__init__(*args)
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

    def __init__(self, *args):
        super().__init__(*args)
        self.binary_service = BinaryService()

    def get_response(self, task: tuple[str, int, int]) -> bytes:
        return self.binary_service.read_partial_binary(*task)


class InterComBackEndTarRepackTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'tar_repack_task'
    OUTGOING_CONNECTION_TYPE = 'tar_repack_task_resp'

    def __init__(self, *args):
        super().__init__(*args)
        self.binary_service = BinaryService()

    def get_response(self, task):
        return self.binary_service.get_repacked_binary_and_file_name(task)


class InterComBackEndBinarySearchTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'binary_search_task'
    OUTGOING_CONNECTION_TYPE = 'binary_search_task_resp'

    def get_response(self, task):
        yara_binary_searcher = YaraBinarySearchScanner()
        search_result = yara_binary_searcher.get_binary_search_result(task)
        return search_result, task


class InterComBackEndDeleteFile(InterComListener):
    CONNECTION_TYPE = 'file_delete_task'

    def __init__(self, *args, unpacking_locks: UnpackingLockManager, db_interface: DbInterfaceCommon):
        super().__init__(*args)
        self.fs_organizer = FSOrganizer()
        self.db = db_interface
        self.unpacking_locks = unpacking_locks

    def pre_process(self, task: set[str], task_id):  # noqa: ARG002
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
            logging.info(f'Deleted {deleted} file(s)')


class InterComBackEndLogsTask(InterComListenerAndResponder):
    CONNECTION_TYPE = 'logs_task'
    OUTGOING_CONNECTION_TYPE = 'logs_task_resp'

    def get_response(self, task):  # noqa: ARG002
        backend_logs = Path(config.backend.logging.file_backend)
        if backend_logs.is_file():
            return backend_logs.read_text().splitlines()[-100:]
        return []

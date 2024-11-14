from __future__ import annotations

import contextlib
import logging
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from multiprocessing import Manager, Process, Queue, Value
from queue import Empty
from time import time
from typing import TYPE_CHECKING

import config
from helperFunctions.process import stop_process
from objects.firmware import Firmware
from storage.redis_status_interface import RedisStatusInterface

if TYPE_CHECKING:
    from objects.file import FileObject

RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC = 300


class _UpdateType(Enum):
    add_update = auto()
    add_firmware = auto()
    add_file = auto()
    add_analysis = auto()
    remove_file = auto()
    is_currently_analyzed = auto()
    cancel = auto()


class AnalysisStatus:
    def __init__(self):
        self._manager = Manager()
        # this object tracks only the FW objects and not the status of the individual files
        self._currently_analyzed = self._manager.dict()
        self._worker = AnalysisStatusWorker(currently_analyzed_fw=self._currently_analyzed)

    def start(self):
        self._worker.start()

    def shutdown(self):
        self._worker.shutdown()
        self._manager.shutdown()

    def add_update(self, fw_object: Firmware | FileObject, included_files: list[str] | set[str]):
        self.add_object(fw_object)
        self._worker.queue.put((_UpdateType.add_update, fw_object.uid, included_files))

    def add_object(self, fw_object: Firmware | FileObject):
        if isinstance(fw_object, Firmware):
            self._worker.queue.put(
                (
                    _UpdateType.add_firmware,
                    fw_object.uid,
                    fw_object.files_included,
                    fw_object.get_hid(),
                    fw_object.scheduled_analysis,
                )
            )
        else:
            self._worker.queue.put(
                (
                    _UpdateType.add_file,
                    fw_object.uid,
                    fw_object.root_uid,
                    fw_object.files_included,
                )
            )

    def add_analysis(self, fw_object: FileObject, plugin: str):
        self._worker.queue.put((_UpdateType.add_analysis, fw_object.root_uid, plugin))

    def remove_object(self, fw_object: Firmware | FileObject):
        self._worker.queue.put((_UpdateType.remove_file, fw_object.uid, fw_object.root_uid))

    def fw_analysis_is_in_progress(self, fw_object: Firmware | FileObject) -> bool:
        return fw_object.root_uid in self._currently_analyzed or fw_object.uid in self._currently_analyzed

    def cancel_analysis(self, root_uid: str):
        self._worker.queue.put((_UpdateType.cancel, root_uid))


@dataclass
class FwAnalysisStatus:
    files_to_unpack: set[str]
    files_to_analyze: set[str]
    total_files_count: int
    hid: str
    analysis_plugins: dict[str, int]
    start_time: float = field(default_factory=time)
    completed_files: set[str] = field(default_factory=set)
    total_files_with_duplicates: int = 1
    unpacked_files_count: int = 1
    analyzed_files_count: int = 0


class AnalysisStatusWorker:
    def __init__(self, currently_analyzed_fw: dict):
        self.recently_finished = {}
        self.recently_canceled = {}
        self.currently_running: dict[str, FwAnalysisStatus] = {}
        self.currently_analyzed: dict = currently_analyzed_fw
        self._worker_process = None
        self.queue = Queue()
        self._running = Value('i', 0)
        self.redis = RedisStatusInterface()

    def start(self):
        self._running.value = 1
        self._worker_process = Process(target=self._worker_loop)
        self._worker_process.start()

    def shutdown(self):
        self._running.value = 0
        if self._worker_process is not None:
            stop_process(self._worker_process, timeout=10)

    def _worker_loop(self):
        logging.debug(f'starting analysis status worker (pid: {os.getpid()})')
        next_update_time = 0
        while self._running.value:
            with contextlib.suppress(Empty):
                self._update_status()

            current_time = time()
            if current_time > next_update_time:
                logging.debug(f'updating status (queue: {self.queue.qsize()})')
                self._clear_recently_finished()
                self._store_status()
                next_update_time = current_time + config.backend.analysis_status_update_interval
        logging.debug('stopped analysis status worker')

    def _update_status(self):
        update_type, *args = self.queue.get(timeout=config.backend.analysis_status_update_interval)
        if update_type == _UpdateType.add_update:
            self._add_update(*args)
        elif update_type == _UpdateType.add_firmware:
            self._add_firmware(*args)
        elif update_type == _UpdateType.add_file:
            self._add_included_file(*args)
        elif update_type == _UpdateType.add_analysis:
            self._add_analysis(*args)
        elif update_type == _UpdateType.remove_file:
            self._remove_object(*args)
        elif update_type == _UpdateType.cancel:
            self._cancel_analysis(*args)

    def _add_update(self, fw_uid: str, included_files: set[str]):
        status = self.currently_running[fw_uid]
        status.files_to_unpack = set()
        file_count = len(included_files) + 1
        status.unpacked_files_count = file_count
        status.total_files_count = file_count
        status.total_files_with_duplicates = file_count
        status.files_to_analyze = {fw_uid, *included_files}

    def _add_firmware(self, uid: str, included_files: set[str], hid: str, scheduled_analyses: list[str] | None):
        self.currently_running[uid] = FwAnalysisStatus(
            files_to_unpack=set(included_files),
            files_to_analyze={uid},
            total_files_count=1 + len(included_files),
            hid=hid,
            analysis_plugins={p: 0 for p in scheduled_analyses or []},
        )
        # This is only for checking if a FW is currently analyzed from *outside* of this class
        self.currently_analyzed[uid] = True

    def _add_included_file(self, uid: str, root_uid: str, included_files: set[str]):
        """
        An included file of a FW comes from unpacking. There are two things that need to be updated:
        - move the file from files_to_unpack to files_to_analyze (could be a duplicate, i.e. was already moved)
        - included files of the file need to be added to files_to_unpack (could also include duplicates)
        """
        if root_uid not in self.currently_running:
            return
        status = self.currently_running[root_uid]
        all_files = status.files_to_unpack.union(status.files_to_analyze)
        new_files = set(included_files) - all_files - status.completed_files
        status.total_files_count += len(new_files)
        status.total_files_with_duplicates += 1
        status.files_to_unpack.update(new_files)
        if uid in status.files_to_unpack:
            status.files_to_unpack.remove(uid)
            status.files_to_analyze.add(uid)
            status.unpacked_files_count += 1

    def _add_analysis(self, root_uid: str, plugin: str):
        if root_uid not in self.currently_running:
            return
        status = self.currently_running[root_uid]
        status.analysis_plugins.setdefault(plugin, 0)
        status.analysis_plugins[plugin] += 1

    def _remove_object(self, uid: str, root_uid: str):
        if root_uid not in self.currently_running:
            return
        status = self.currently_running[root_uid]
        if uid not in status.files_to_analyze:
            # probably a file that occurred multiple times in one firmware
            logging.debug(f'Failed to remove {uid} from current analysis of {root_uid}')
            return
        status.files_to_analyze.remove(uid)
        status.completed_files.add(uid)
        status.analyzed_files_count += 1
        if len(status.files_to_unpack) == len(status.files_to_analyze) == 0:
            self.recently_finished[root_uid] = self._init_recently_finished(status)
            del self.currently_running[root_uid]
            self.currently_analyzed.pop(root_uid, None)
            logging.info(f'Analysis of firmware {root_uid} completed')

    @staticmethod
    def _init_recently_finished(analysis_status: FwAnalysisStatus) -> dict:
        return {
            'duration': time() - analysis_status.start_time,
            'total_files_count': analysis_status.total_files_count,
            'time_finished': time(),
            'hid': analysis_status.hid,
        }

    def _clear_recently_finished(self):
        for status_dict in (self.recently_finished, self.recently_canceled):
            for uid, stats in list(status_dict.items()):
                if time() - stats['time_finished'] > RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC:
                    status_dict.pop(uid)

    def _store_status(self):
        status = {
            'current_analyses': self._get_current_analyses_stats(),
            'recently_finished_analyses': self.recently_finished,
            'recently_canceled_analyses': self.recently_canceled,
        }
        self.redis.set_analysis_status(status)

    def _get_current_analyses_stats(self):
        return {
            uid: {
                'unpacked_count': status.unpacked_files_count,
                'analyzed_count': status.analyzed_files_count,
                'start_time': status.start_time,
                'total_count': status.total_files_count,
                'total_count_with_duplicates': status.total_files_with_duplicates,
                'hid': status.hid,
                'plugins': status.analysis_plugins,
            }
            for uid, status in self.currently_running.items()
        }

    def _cancel_analysis(self, root_uid: str):
        if root_uid in self.currently_running:
            status = self.currently_running.pop(root_uid)
            self.recently_canceled[root_uid] = {
                'unpacked_count': status.unpacked_files_count,
                'analyzed_count': status.analyzed_files_count,
                'total_count': status.total_files_count,
                'hid': status.hid,
                'time_finished': time(),
            }
            self.currently_analyzed.pop(root_uid, None)

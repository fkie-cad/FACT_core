from __future__ import annotations

import logging
from contextlib import contextmanager
from multiprocessing import Manager
from time import time
from typing import TYPE_CHECKING

from objects.firmware import Firmware

if TYPE_CHECKING:
    from objects.file import FileObject

RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC = 300


class AnalysisStatus:
    def __init__(self):
        self.manager = Manager()
        logging.debug(f'Started AnalysisStatus manager {getattr(self.manager, "._process", "")}')

        self.currently_running = self.manager.dict()
        self.recently_finished = self.manager.dict()
        self.currently_running_lock = self.manager.Lock()

    def shutdown(self):
        self.manager.shutdown()

    def add_update_to_current_analyses(self, fw_object: Firmware | FileObject, included_files: list[str] | set[str]):
        self.add_to_current_analyses(fw_object)
        with self._get_lock():
            update_dict = self.currently_running[fw_object.uid]
            update_dict['files_to_unpack'] = set()
            file_count = len(included_files) + 1
            update_dict['unpacked_files_count'] = file_count
            update_dict['total_files_count'] = file_count
            update_dict['total_files_with_duplicates'] = file_count
            update_dict['files_to_analyze'] = {fw_object.uid, *included_files}
            self.currently_running[fw_object.uid] = update_dict

    def add_to_current_analyses(self, fw_object: Firmware | FileObject):
        with self._get_lock():
            if isinstance(fw_object, Firmware):
                self.currently_running[fw_object.uid] = self._init_current_analysis(fw_object)
            else:
                self._update_current_analysis(fw_object)

    def _update_current_analysis(self, fw_object: FileObject):
        """
        new file comes from unpacking:
        - file moved from files_to_unpack to files_to_analyze (could be duplicate!)
        - included files added to files_to_unpack (could also include duplicates!)
        """
        for parent in self._find_currently_analyzed_parents(fw_object):
            updated_dict = self.currently_running[parent]
            all_files = updated_dict['files_to_unpack'].union(updated_dict['files_to_analyze'])
            new_files = set(fw_object.files_included) - all_files - updated_dict['completed_files']
            updated_dict['total_files_count'] += len(new_files)
            updated_dict['total_files_with_duplicates'] += 1
            updated_dict['files_to_unpack'].update(new_files)
            if fw_object.uid in updated_dict['files_to_unpack']:
                updated_dict['files_to_unpack'].remove(fw_object.uid)
                updated_dict['files_to_analyze'].add(fw_object.uid)
                updated_dict['unpacked_files_count'] += 1
            self.currently_running[parent] = updated_dict

    def update_post_analysis(self, fw_object: FileObject, plugin: str):
        with self._get_lock():
            for parent in self._find_currently_analyzed_parents(fw_object):
                updated_dict = self.currently_running[parent]
                updated_dict['analysis_plugins'].setdefault(plugin, 0)
                updated_dict['analysis_plugins'][plugin] += 1
                self.currently_running[parent] = updated_dict

    @staticmethod
    def _init_current_analysis(fw_object: Firmware):
        return {
            'files_to_unpack': set(fw_object.files_included),
            'files_to_analyze': {fw_object.uid},
            'completed_files': set(),
            'start_time': time(),
            'unpacked_files_count': 1,
            'analyzed_files_count': 0,
            'total_files_count': 1 + len(fw_object.files_included),
            'total_files_with_duplicates': 1,
            'hid': fw_object.get_hid(),
            'analysis_plugins': {p: 0 for p in fw_object.scheduled_analysis or []},
        }

    def remove_from_current_analyses(self, fw_object: Firmware | FileObject):
        with self._get_lock():
            for parent in self._find_currently_analyzed_parents(fw_object):
                updated_dict = self.currently_running[parent]
                if fw_object.uid not in updated_dict['files_to_analyze']:
                    # probably a file that occurred multiple times in one firmware
                    logging.debug(f'Failed to remove {fw_object.uid} from current analysis of {parent}')
                    continue
                updated_dict['files_to_analyze'].remove(fw_object.uid)
                updated_dict['completed_files'].add(fw_object.uid)
                updated_dict['analyzed_files_count'] += 1
                if len(updated_dict['files_to_unpack']) == len(updated_dict['files_to_analyze']) == 0:
                    self.recently_finished[parent] = self._init_recently_finished(updated_dict)
                    self.currently_running.pop(parent)
                    logging.info(f'Analysis of firmware {parent} completed')
                else:
                    self.currently_running[parent] = updated_dict

    def file_should_be_analyzed(self, fw_object: Firmware | FileObject) -> bool:
        if isinstance(fw_object, Firmware):
            return True
        # the file should already have been added as an included file of its parent -> if it's missing it is a duplicate
        with self._get_lock():
            if fw_object.root_uid not in self.currently_running:
                return False  # analysis (of all non-duplicates) is already completed
            return (
                fw_object.uid not in self.currently_running[fw_object.root_uid]['completed_files']
                and fw_object.uid in self.currently_running[fw_object.root_uid]['files_to_unpack']
            )

    @contextmanager
    def _get_lock(self):
        try:
            self.currently_running_lock.acquire()
            yield
        finally:
            self.currently_running_lock.release()

    @staticmethod
    def _init_recently_finished(analysis_data: dict) -> dict:
        return {
            'duration': time() - analysis_data['start_time'],
            'total_files_count': analysis_data['total_files_count'],
            'time_finished': time(),
            'hid': analysis_data['hid'],
        }

    def _find_currently_analyzed_parents(self, fw_object: Firmware | FileObject) -> set[str]:
        # FileObject.root_uid should be set to the correct root_uid during unpacking
        parent_fw_uid = fw_object.uid if isinstance(fw_object, Firmware) else fw_object.root_uid
        return set(self.currently_running.keys()).intersection({parent_fw_uid})

    def get_current_analyses_stats(self):
        return {
            uid: {
                'unpacked_count': stats_dict['unpacked_files_count'],
                'analyzed_count': stats_dict['analyzed_files_count'],
                'start_time': stats_dict['start_time'],
                'total_count': stats_dict['total_files_count'],
                'total_count_with_duplicates': stats_dict['total_files_with_duplicates'],
                'hid': stats_dict['hid'],
                'plugins': stats_dict['analysis_plugins'],
            }
            for uid, stats_dict in self.currently_running.items()
        }

    def clear_recently_finished(self):
        with self._get_lock():
            for uid, stats in list(self.recently_finished.items()):
                if time() - stats['time_finished'] > RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC:
                    self.recently_finished.pop(uid)

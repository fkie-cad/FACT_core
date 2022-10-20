import logging
from multiprocessing import Manager
from time import time
from typing import List, Set, Union

from objects.file import FileObject
from objects.firmware import Firmware

RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC = 300


class AnalysisStatus:
    def __init__(self):
        self.manager = Manager()

        self.currently_running = self.manager.dict()
        self.recently_finished = self.manager.dict()
        self.currently_running_lock = self.manager.Lock()  # pylint: disable=no-member

    def add_update_to_current_analyses(self, fw_object: Union[Firmware, FileObject], included_files: List[str]):
        self.add_to_current_analyses(fw_object)
        self.currently_running_lock.acquire()
        update_dict = self.currently_running[fw_object.uid]
        update_dict['files_to_unpack'] = []
        update_dict['unpacked_files_count'] = len(included_files) + 1
        update_dict['total_files_count'] = len(included_files) + 1
        update_dict['files_to_analyze'] = [fw_object.uid, *included_files]
        self.currently_running[fw_object.uid] = update_dict
        self.currently_running_lock.release()

    def add_to_current_analyses(self, fw_object: Union[Firmware, FileObject]):
        self.currently_running_lock.acquire()
        try:
            if isinstance(fw_object, Firmware):
                self.currently_running[fw_object.uid] = self._init_current_analysis(fw_object)
            else:
                self._update_current_analysis(fw_object)
        finally:
            self.currently_running_lock.release()

    def _update_current_analysis(self, fw_object):
        '''
        new file comes from unpacking:
        - file moved from files_to_unpack to files_to_analyze (could be duplicate!)
        - included files added to files_to_unpack (could also include duplicates!)
        '''
        for parent in self._find_currently_analyzed_parents(fw_object):
            updated_dict = self.currently_running[parent]
            new_files = set(fw_object.files_included) - set(updated_dict['files_to_unpack']).union(
                set(updated_dict['files_to_analyze'])
            )
            updated_dict['total_files_count'] += len(new_files)
            updated_dict['files_to_unpack'] = list(set(updated_dict['files_to_unpack']).union(new_files))
            if fw_object.uid in updated_dict['files_to_unpack']:
                updated_dict['files_to_unpack'].remove(fw_object.uid)
                updated_dict['files_to_analyze'].append(fw_object.uid)
                updated_dict['unpacked_files_count'] += 1
            self.currently_running[parent] = updated_dict

    @staticmethod
    def _init_current_analysis(fw_object: Firmware):
        return {
            'files_to_unpack': list(fw_object.files_included),
            'files_to_analyze': [fw_object.uid],
            'start_time': time(),
            'unpacked_files_count': 1,
            'analyzed_files_count': 0,
            'total_files_count': 1 + len(fw_object.files_included),
            'hid': fw_object.get_hid(),
        }

    def remove_from_current_analyses(self, fw_object: Union[Firmware, FileObject]):
        try:
            self.currently_running_lock.acquire()
            for parent in self._find_currently_analyzed_parents(fw_object):
                updated_dict = self.currently_running[parent]
                if fw_object.uid not in updated_dict['files_to_analyze']:
                    # probably a file that occurred multiple times in one firmware
                    logging.debug(f'Failed to remove {fw_object.uid} from current analysis of {parent}')
                    continue
                updated_dict['files_to_analyze'] = list(set(updated_dict['files_to_analyze']) - {fw_object.uid})
                updated_dict['analyzed_files_count'] += 1
                if len(updated_dict['files_to_unpack']) == len(updated_dict['files_to_analyze']) == 0:
                    self.recently_finished[parent] = self._init_recently_finished(updated_dict)
                    self.currently_running.pop(parent)
                    logging.info(f'Analysis of firmware {parent} completed')
                else:
                    self.currently_running[parent] = updated_dict
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

    def _find_currently_analyzed_parents(self, fw_object: Union[Firmware, FileObject]) -> Set[str]:
        parent_uids = {fw_object.uid} if isinstance(fw_object, Firmware) else fw_object.parent_firmware_uids
        return set(self.currently_running.keys()).intersection(parent_uids)

    def get_current_analyses_stats(self):
        return {
            uid: {
                'unpacked_count': stats_dict['unpacked_files_count'],
                'analyzed_count': stats_dict['analyzed_files_count'],
                'start_time': stats_dict['start_time'],
                'total_count': stats_dict['total_files_count'],
                'hid': stats_dict['hid'],
            }
            for uid, stats_dict in self.currently_running.items()
        }

    def clear_recently_finished(self):
        try:
            self.currently_running_lock.acquire()
            for uid, stats in list(self.recently_finished.items()):
                if time() - stats['time_finished'] > RECENTLY_FINISHED_DISPLAY_TIME_IN_SEC:
                    self.recently_finished.pop(uid)
        finally:
            self.currently_running_lock.release()

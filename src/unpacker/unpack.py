from __future__ import annotations

import json
import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from time import time

from fact_helper_file import get_file_type_from_path

from config import cfg
from helperFunctions.fileSystem import file_is_empty, get_relative_object_path
from helperFunctions.tag import TagColor
from helperFunctions.virtual_file_path import get_base_of_virtual_path, join_virtual_path
from objects.file import FileObject
from storage.fsorganizer import FSOrganizer
from unpacker.unpack_base import UnpackBase


class Unpacker(UnpackBase):
    def __init__(self, worker_id=None, fs_organizer=None, unpacking_locks=None):
        super().__init__(worker_id=worker_id)
        self.file_storage_system = FSOrganizer() if fs_organizer is None else fs_organizer
        self.unpacking_locks = unpacking_locks

    def unpack(self, current_fo: FileObject) -> list[FileObject]:
        '''
        Recursively extract all objects included in current_fo and add them to current_fo.files_included
        '''

        logging.debug(f'[worker {self.worker_id}] Extracting {current_fo.uid}: Depth: {current_fo.depth}')

        if current_fo.depth >= cfg.unpack.max_depth:
            logging.warning(f'{current_fo.uid} is not extracted since depth limit ({cfg.unpack.max_depth}) is reached')
            self._store_unpacking_depth_skip_info(current_fo)
            return []

        with TemporaryDirectory(prefix='fact_unpack_', dir=cfg.data_storage.docker_mount_base_dir) as tmp_dir:
            file_path = self._generate_local_file_path(current_fo)
            extracted_files = self.extract_files_from_file(file_path, tmp_dir)
            if extracted_files is None:
                self._store_unpacking_error_skip_info(current_fo)
                return []

            extracted_file_objects = self.generate_objects_and_store_files(
                extracted_files, Path(tmp_dir) / 'files', current_fo
            )
            self.add_included_files_to_object(extracted_file_objects, current_fo)
            # set meta data
            current_fo.processed_analysis['unpacker'] = json.loads(
                Path(tmp_dir, 'reports', 'meta.json').read_text()  # pylint: disable=unspecified-encoding
            )

        return extracted_file_objects

    def _store_unpacking_error_skip_info(self, file_object: FileObject):
        file_object.processed_analysis['unpacker'] = self._init_skipped_analysis(
            'Unpacking stopped because extractor raised a exception (possible timeout)',
            'extractor error',
            'possible extractor timeout',
        )

    def _store_unpacking_depth_skip_info(self, file_object: FileObject):
        file_object.processed_analysis['unpacker'] = self._init_skipped_analysis(
            'Unpacking stopped because maximum unpacking depth was reached',
            'depth reached',
            'unpacking depth reached',
        )

    @staticmethod
    def _init_skipped_analysis(message: str, tag: str, tag_tooltip: str) -> dict:
        return {
            'plugin_used': 'None',
            'number_of_unpacked_files': 0,
            'plugin_version': '0.0',
            'analysis_date': time(),
            'info': message,
            'tags': {tag: {'value': tag_tooltip, 'color': TagColor.ORANGE, 'propagate': False}},
        }

    def cleanup(self, tmp_dir):
        try:
            tmp_dir.cleanup()
        except OSError as error:
            logging.error(f'[worker {self.worker_id}] Could not CleanUp tmp_dir: {type(error)} - {str(error)}')

    @staticmethod
    def add_included_files_to_object(included_file_objects: list[FileObject], root_file_object: FileObject):
        for item in included_file_objects:
            root_file_object.add_included_file(item)

    def generate_objects_and_store_files(
        self, file_paths: list[Path], extraction_dir: Path, parent: FileObject
    ) -> list[FileObject]:
        extracted_files = {}
        for item in file_paths:
            if file_is_empty(item):
                continue
            current_file = FileObject(file_path=str(item))
            base = get_base_of_virtual_path(parent.get_virtual_file_paths()[parent.get_root_uid()][0])
            current_virtual_path = join_virtual_path(base, parent.uid, get_relative_object_path(item, extraction_dir))
            current_file.temporary_data['parent_fo_type'] = get_file_type_from_path(parent.file_path)['mime']
            if current_file.uid in extracted_files:  # the same file is extracted multiple times from one archive
                extracted_files[current_file.uid].virtual_file_path[parent.get_root_uid()].append(current_virtual_path)
            else:
                self.unpacking_locks.set_unpacking_lock(current_file.uid)
                self.file_storage_system.store_file(current_file)
                current_file.virtual_file_path = {parent.get_root_uid(): [current_virtual_path]}
                current_file.parent_firmware_uids.add(parent.get_root_uid())
                extracted_files[current_file.uid] = current_file
        extracted_files.pop(parent.uid, None)  # the same file should not be unpacked from itself
        return list(extracted_files.values())

    def _generate_local_file_path(self, file_object: FileObject) -> str:
        if not Path(file_object.file_path).exists():
            local_path = self.file_storage_system.generate_path(file_object.uid)
            return local_path
        return file_object.file_path

import json
import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from time import time
from typing import Dict, List

from fact_helper_file import get_file_type_from_path

from helperFunctions.fileSystem import file_is_empty, get_relative_object_path
from helperFunctions.tag import TagColor
from helperFunctions.virtual_file_path import get_base_of_virtual_path, join_virtual_path
from objects.file import FileObject
from storage.fsorganizer import FSOrganizer
from unpacker.unpack_base import UnpackBase


class Unpacker(UnpackBase):
    def __init__(self, config, unpacking_locks):
        self.config = config
        self.file_storage_system = FSOrganizer(config=self.config)
        self.unpacking_locks = unpacking_locks

    def unpack(self, current_fo: FileObject, container_url: str, tmp_dir: TemporaryDirectory) -> List[FileObject]:
        if current_fo.depth >= self.config.getint('unpack', 'max-depth'):
            logging.warning(
                f'{current_fo.uid} is not extracted since depth limit'
                f' ({self.config.get("unpack", "max-depth")}) is reached'
            )
            self._store_unpacking_depth_skip_info(current_fo)
            return []

        file_path = self._generate_local_file_path(current_fo)
        extracted_files = self.extract_files_from_file(file_path, tmp_dir.name, container_url)
        if extracted_files is None:
            self._store_unpacking_error_skip_info(current_fo)
            return []

        extracted_file_objects = self.generate_and_store_file_objects(
            extracted_files, Path(tmp_dir.name) / 'files', current_fo
        )
        extracted_file_objects = self.remove_duplicates(extracted_file_objects, current_fo)
        self.add_included_files_to_object(extracted_file_objects, current_fo)

        current_fo.processed_analysis['unpacker'] = json.loads(Path(tmp_dir.name, 'reports', 'meta.json').read_text())
        return extracted_file_objects

    @staticmethod
    def _store_unpacking_error_skip_info(file_object: FileObject):
        file_object.processed_analysis['unpacker'] = {
            'plugin_used': 'None',
            'number_of_unpacked_files': 0,
            'plugin_version': '0.0',
            'analysis_date': time(),
            'info': 'Unpacking stopped because extractor raised a exception (possible timeout)',
            'tags': {
                'extractor error': {'value': 'possible extractor timeout', 'color': TagColor.ORANGE, 'propagate': False}
            },
        }

    @staticmethod
    def _store_unpacking_depth_skip_info(file_object: FileObject):
        file_object.processed_analysis['unpacker'] = {
            'plugin_used': 'None',
            'number_of_unpacked_files': 0,
            'plugin_version': '0.0',
            'analysis_date': time(),
            'info': 'Unpacking stopped because maximum unpacking depth was reached',
            'tags': {
                'depth reached': {'value': 'unpacking depth reached', 'color': TagColor.ORANGE, 'propagate': False}
            },
        }

    @staticmethod
    def add_included_files_to_object(included_file_objects, root_file_object):
        for item in included_file_objects:
            root_file_object.add_included_file(item)

    def generate_and_store_file_objects(
        self, file_paths: List[Path], extraction_dir: Path, parent: FileObject
    ) -> Dict[str, FileObject]:
        extracted_files = {}
        for item in file_paths:
            if not file_is_empty(item):
                current_file = FileObject(file_path=str(item))
                base = get_base_of_virtual_path(parent.get_virtual_file_paths()[parent.get_root_uid()][0])
                current_virtual_path = join_virtual_path(
                    base, parent.uid, get_relative_object_path(item, extraction_dir)
                )
                current_file.temporary_data['parent_fo_type'] = get_file_type_from_path(parent.file_path)['mime']
                if current_file.uid in extracted_files:  # the same file is extracted multiple times from one archive
                    extracted_files[current_file.uid].virtual_file_path[parent.get_root_uid()].append(
                        current_virtual_path
                    )
                else:
                    self.unpacking_locks.set_unpacking_lock(current_file.uid)
                    self.file_storage_system.store_file(current_file)
                    current_file.virtual_file_path = {parent.get_root_uid(): [current_virtual_path]}
                    current_file.parent_firmware_uids.add(parent.get_root_uid())
                    extracted_files[current_file.uid] = current_file
        return extracted_files

    @staticmethod
    def remove_duplicates(extracted_fo_dict, parent_fo) -> List[FileObject]:
        if parent_fo.uid in extracted_fo_dict:
            del extracted_fo_dict[parent_fo.uid]
        return list(extracted_fo_dict.values())

    def _generate_local_file_path(self, file_object: FileObject):
        if not Path(file_object.file_path).exists():
            local_path = self.file_storage_system.generate_path(file_object.uid)
            return local_path
        return file_object.file_path

import json
import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List

from fact_helper_file import get_file_type_from_path

from helperFunctions.dataConversion import make_list_from_dict, make_unicode_string
from helperFunctions.fileSystem import file_is_empty, get_object_path_excluding_fact_dirs
from helperFunctions.tag import TagColor
from objects.file import FileObject
from storage.fs_organizer import FS_Organizer
from unpacker.unpack_base import UnpackBase


class Unpacker(UnpackBase):
    def __init__(self, config=None, worker_id=None, db_interface=None):
        super().__init__(config=config, worker_id=worker_id)
        self.file_storage_system = FS_Organizer(config=self.config)
        self.db_interface = db_interface

    def unpack(self, current_fo: FileObject):
        '''
        Recursively extract all objects included in current_fo and add them to current_fo.files_included
        '''

        logging.debug('[worker {}] Extracting {}: Depth: {}'.format(self.worker_id, current_fo.uid, current_fo.depth))

        if current_fo.depth >= self.config.getint('unpack', 'max_depth'):
            logging.warning('{} is not extracted since depth limit ({}) is reached'.format(current_fo.uid, self.config.get('unpack', 'max_depth')))
            self._store_unpacking_depth_skip_info(current_fo)
            return []

        tmp_dir = TemporaryDirectory(prefix='fact_unpack_')

        file_path = self._generate_local_file_path(current_fo)

        extracted_files = self.extract_files_from_file(file_path, tmp_dir.name)

        extracted_file_objects = self.generate_and_store_file_objects(extracted_files, tmp_dir.name, current_fo)
        extracted_file_objects = self.remove_duplicates(extracted_file_objects, current_fo)
        self.add_included_files_to_object(extracted_file_objects, current_fo)

        # set meta data
        current_fo.processed_analysis['unpacker'] = json.loads(Path(tmp_dir.name, 'reports', 'meta.json').read_text())

        self.cleanup(tmp_dir)
        return extracted_file_objects

    @staticmethod
    def _store_unpacking_depth_skip_info(file_object: FileObject):
        file_object.processed_analysis['unpacker'] = {
            'plugin_used': 'None', 'number_of_unpacked_files': 0,
            'info': 'Unpacking stopped because maximum unpacking depth was reached',
        }
        tag_dict = {'unpacker': {'depth reached': {'value': 'unpacking depth reached', 'color': TagColor.ORANGE, 'propagate': False}}}
        file_object.analysis_tags.update(tag_dict)

    def cleanup(self, tmp_dir):
        try:
            tmp_dir.cleanup()
        except OSError as error:
            logging.error('[worker {}] Could not CleanUp tmp_dir: {} - {}'.format(self.worker_id, type(error), str(error)))

    @staticmethod
    def add_included_files_to_object(included_file_objects, root_file_object):
        for item in included_file_objects:
            root_file_object.add_included_file(item)

    def generate_and_store_file_objects(self, file_paths: List[Path], extractor_dir: str, parent: FileObject):
        extracted_files = {}
        for item in file_paths:
            if not file_is_empty(item):
                current_file = FileObject(file_path=str(item))
                current_virtual_path = '{}|{}|{}'.format(
                    parent.get_base_of_virtual_path(parent.get_virtual_file_paths()[parent.get_root_uid()][0]),
                    parent.uid, get_object_path_excluding_fact_dirs(make_unicode_string(str(item)), str(Path(extractor_dir, 'files')))
                )
                current_file.temporary_data['parent_fo_type'] = get_file_type_from_path(parent.file_path)['mime']
                if current_file.uid in extracted_files:  # the same file is extracted multiple times from one archive
                    extracted_files[current_file.uid].virtual_file_path[parent.get_root_uid()].append(current_virtual_path)
                else:
                    self.db_interface.set_unpacking_lock(current_file.uid)
                    self.file_storage_system.store_file(current_file)
                    current_file.virtual_file_path = {parent.get_root_uid(): [current_virtual_path]}
                    current_file.parent_firmware_uids.add(parent.get_root_uid())
                    extracted_files[current_file.uid] = current_file
        return extracted_files

    @staticmethod
    def remove_duplicates(extracted_fo_dict, parent_fo):
        if parent_fo.uid in extracted_fo_dict:
            del extracted_fo_dict[parent_fo.uid]
        return make_list_from_dict(extracted_fo_dict)

    def _generate_local_file_path(self, file_object: FileObject):
        if not Path(file_object.file_path).exists():
            local_path = self.file_storage_system.generate_path(file_object.uid)
            return local_path
        return file_object.file_path

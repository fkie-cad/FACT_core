import json
import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List
import os

from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.dataConversion import make_unicode_string, make_list_from_dict
from helperFunctions.fileSystem import get_chroot_path_excluding_extracted_dir, get_file_type_from_path, file_is_empty
from objects.file import FileObject
from storage.fs_organizer import FS_Organizer
from unpacker.unpackBase import UnpackBase


class Unpacker(UnpackBase):
    def __init__(self, config=None, worker_id=None, db_interface=None):
        super().__init__(config=config, worker_id=worker_id)
        self.file_storage_system = FS_Organizer(config=self.config)
        self.db_interface = db_interface

    def unpack(self, current_fo: FileObject):
        '''
        Recursively extract all objects included in current_fo and add them to current_fo.files_included
        '''

        logging.debug('[worker {}] Extracting {}: Depth: {}'.format(self.worker_id, current_fo.get_uid(), current_fo.depth))

        if current_fo.depth >= self.config.getint('unpack', 'max_depth'):
            logging.warning('{} is not extracted since depth limit ({}) is reached'.format(current_fo.get_uid(), self.config.get('unpack', 'max_depth')))
            return []

        tmp_dir = TemporaryDirectory(prefix='faf_unpack_')
        self._initialize_shared_folder(tmp_dir)

        # Call docker container
        Path(tmp_dir.name, 'input', current_fo.file_name).write_bytes(current_fo.binary)
        output, return_code = execute_shell_command_get_return_code('docker run -v {}:/tmp/extractor --rm fact_extractor'.format(tmp_dir.name))
        if return_code != 0:
            error = 'Failed to execute docker extractor with code {}:\n{}'.format(return_code, output)
            logging.error(error)
            raise RuntimeError(error)

        # store extracted files in data storage
        all_items = list(Path(tmp_dir.name, 'files').glob('**/*'))
        extracted_files = [item for item in all_items if not item.is_dir()]
        extracted_file_objects = self.generate_and_store_file_objects(extracted_files, tmp_dir.name, current_fo)
        extracted_file_objects = self.remove_duplicates(extracted_file_objects, current_fo)
        self.add_included_files_to_object(extracted_file_objects, current_fo)

        # set meta data
        current_fo.processed_analysis['unpacker'] = json.loads(Path(tmp_dir.name, 'reports', 'meta.json').read_text())

        self.cleanup(tmp_dir)
        return extracted_file_objects

    def cleanup(self, tmp_dir):
        try:
            tmp_dir.cleanup()
        except Exception as e:
            logging.error('[worker {}] Could not CleanUp tmp_dir: {} - {}'.format(self.worker_id, type(e), str(e)))

    @staticmethod
    def add_included_files_to_object(included_file_objects, root_file_object):
        for item in included_file_objects:
            root_file_object.add_included_file(item)

    @staticmethod
    def _initialize_shared_folder(tmp_dir):
        for subpath in ['files', 'reports', 'input']:
            os.makedirs(str(Path(tmp_dir.name, subpath)), exist_ok=True)

    def generate_and_store_file_objects(self, file_paths: List[Path], tmp_dir, parent: FileObject):
        extracted_files = {}
        for item in file_paths:
            if not file_is_empty(item):
                current_file = FileObject(file_path=item)
                current_virtual_path = '{}|{}|{}'.format(
                    parent.get_base_of_virtual_path(parent.get_virtual_file_paths()[parent.get_root_uid()][0]),
                    parent.get_uid(), get_chroot_path_excluding_extracted_dir(make_unicode_string(item), tmp_dir)
                )
                current_file.temporary_data['parent_fo_type'] = get_file_type_from_path(parent.file_path)['mime']
                if current_file.get_uid() in extracted_files:  # the same file is extracted multiple times from one archive
                    extracted_files[current_file.get_uid()].virtual_file_path[parent.get_root_uid()].append(current_virtual_path)
                else:
                    self.db_interface.set_unpacking_lock(current_file.uid)
                    self.file_storage_system.store_file(current_file)
                    current_file.virtual_file_path = {parent.get_root_uid(): [current_virtual_path]}
                    current_file.parent_firmware_uids.add(parent.get_root_uid())
                    extracted_files[current_file.get_uid()] = current_file
        return extracted_files

    @staticmethod
    def remove_duplicates(extracted_fo_dict, parent_fo):
        if parent_fo.get_uid() in extracted_fo_dict:
            del extracted_fo_dict[parent_fo.get_uid()]
        return make_list_from_dict(extracted_fo_dict)

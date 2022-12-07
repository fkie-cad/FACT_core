import logging
from pathlib import Path

from common_helper_files import delete_file, write_binary_to_file

from config import cfg


class FSOrganizer:
    '''
    This module organizes file system storage
    '''

    def __init__(self):
        self.data_storage_path = Path(cfg.data_storage.firmware_file_storage_directory).absolute()

        self.data_storage_path.parent.mkdir(parents=True, exist_ok=True)

    def store_file(self, file_object):
        if file_object.binary is None:
            logging.error('Cannot store binary! No binary data specified')
        else:
            destination_path = self.generate_path(file_object)
            write_binary_to_file(file_object.binary, destination_path, overwrite=False)
            file_object.file_path = destination_path
            file_object.create_binary_from_path()

    def delete_file(self, uid):
        local_file_path = self.generate_path_from_uid(uid)
        delete_file(local_file_path)

    def generate_path(self, file_object):
        return self.generate_path_from_uid(file_object.uid)

    def generate_path_from_uid(self, uid):
        return str(self.data_storage_path / uid[0:2] / uid)

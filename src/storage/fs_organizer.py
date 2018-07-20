import logging
import os

from common_helper_files import write_binary_to_file, create_dir_for_file, delete_file

from helperFunctions.fileSystem import get_absolute_path


class FS_Organizer(object):
    '''
    This module organizes file system storage
    '''

    def __init__(self, config=None):
        self.config = config
        self.data_storage_path = get_absolute_path(self.config['data_storage']['firmware_file_storage_directory'])
        create_dir_for_file(self.data_storage_path)

    def store_file(self, file_object):
        if file_object.binary is None:
            logging.error('Cannot store binary! No binary data specified')
        else:
            destination_path = self.generate_path(file_object)
            write_binary_to_file(file_object.binary, destination_path, overwrite=False)
            file_object.set_file_path(destination_path)

    def delete_file(self, uid):
        local_file_path = self.generate_path_from_uid(uid)
        delete_file(local_file_path)

    def generate_path(self, file_object):
        return self.generate_path_from_uid(file_object.get_uid())

    def generate_path_from_uid(self, uid):
        return os.path.join(self.data_storage_path, uid[0:2], uid)

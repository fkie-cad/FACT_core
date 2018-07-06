import logging

from common_helper_files.fail_safe_file_operations import get_binary_from_file

from storage.db_interface_common import MongoInterfaceCommon
from unpacker.tar_repack import TarRepack


class BinaryService(object):
    '''
    This is a binary and database backend providing basic return functions
    '''

    def __init__(self, config=None):
        self.config = config
        logging.info("binary service online")

    def get_binary_and_file_name(self, uid):
        tmp = self._get_file_name_and_path_from_db(uid)
        if tmp is None:
            return None, None
        else:
            binary = get_binary_from_file(tmp['file_path'])
            return (binary, tmp['file_name'])

    def get_repacked_binary_and_file_name(self, uid):
        tmp = self._get_file_name_and_path_from_db(uid)
        if tmp is None:
            return None, None
        else:
            repack_service = TarRepack(config=self.config)
            tar = repack_service.tar_repack(tmp['file_path'])
            name = "{}.tar.gz".format(tmp['file_name'])
            return (tar, name)

    def _get_file_name_and_path_from_db(self, uid):
        db_service = BinaryServiceDbInterface(config=self.config)
        tmp = db_service.get_file_name_and_path(uid)
        db_service.shutdown()
        return tmp


class BinaryServiceDbInterface(MongoInterfaceCommon):

    READ_ONLY = True

    def get_file_name_and_path(self, uid):
        result = self.firmwares.find_one({"_id": uid}, {'file_name': 1, 'file_path': 1})
        if result is None:
            result = self.file_objects.find_one({"_id": uid}, {'file_name': 1, 'file_path': 1})
        return result

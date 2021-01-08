import logging
from pathlib import Path

from common_helper_files.fail_safe_file_operations import get_binary_from_file

from helperFunctions.database import ConnectTo
from storage.db_interface_common import MongoInterfaceCommon
from unpacker.tar_repack import TarRepack


class BinaryService:
    '''
    This is a binary and database backend providing basic return functions
    '''

    def __init__(self, config=None):
        self.config = config
        self.firmware_storage_directory = Path(self.config['data_storage']['firmware_file_storage_directory'])
        logging.info("binary service online")

    def get_binary_and_file_name(self, uid):
        query = self._get_file_name_from_db(uid)
        if query is None:
            return None, None
        binary = get_binary_from_file(self._get_file_path(uid))
        return binary, query['file_name']

    def get_repacked_binary_and_file_name(self, uid):
        query = self._get_file_name_from_db(uid)
        if query is None:
            return None, None
        repack_service = TarRepack(config=self.config)
        tar = repack_service.tar_repack(self._get_file_path(uid))
        name = "{}.tar.gz".format(query['file_name'])
        return tar, name

    def _get_file_path(self, uid: str) -> str:
        return str(self.firmware_storage_directory / uid[:2] / uid)

    def _get_file_name_from_db(self, uid):
        with ConnectTo(BinaryServiceDbInterface, self.config) as db_service:
            query = db_service.get_file_name(uid)
        return query


class BinaryServiceDbInterface(MongoInterfaceCommon):

    READ_ONLY = True

    def get_file_name(self, uid):
        result = self.firmwares.find_one({"_id": uid}, {'file_name': 1})
        if result is None:
            result = self.file_objects.find_one({"_id": uid}, {'file_name': 1})
        return result

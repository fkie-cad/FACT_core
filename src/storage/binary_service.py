import logging
from typing import Optional, Tuple

from common_helper_files.fail_safe_file_operations import get_binary_from_file

from helperFunctions.database import ConnectTo
from storage.db_interface_common import MongoInterfaceCommon
from storage.fsorganizer import FSOrganizer
from unpacker.tar_repack import TarRepack


class BinaryService:
    '''
    This is a binary and database backend providing basic return functions
    '''

    def __init__(self, config=None):
        self.config = config
        self.fs_organizer = FSOrganizer(config=config)
        logging.info("binary service online")

    def get_binary_and_file_name(self, uid: str) -> Tuple[Optional[bytes], Optional[str]]:
        file_name = self._get_file_name_from_db(uid)
        if file_name is None:
            return None, None
        binary = get_binary_from_file(self.fs_organizer.generate_path_from_uid(uid))
        return binary, file_name

    def get_repacked_binary_and_file_name(self, uid: str) -> Tuple[Optional[bytes], Optional[str]]:
        file_name = self._get_file_name_from_db(uid)
        if file_name is None:
            return None, None
        repack_service = TarRepack(config=self.config)
        tar = repack_service.tar_repack(self.fs_organizer.generate_path_from_uid(uid))
        name = "{}.tar.gz".format(file_name)
        return tar, name

    def _get_file_name_from_db(self, uid: str) -> Optional[str]:
        with ConnectTo(BinaryServiceDbInterface, self.config) as db_service:
            return db_service.get_file_name(uid)


class BinaryServiceDbInterface(MongoInterfaceCommon):

    READ_ONLY = True

    def get_file_name(self, uid: str) -> Optional[str]:
        result = self.firmwares.find_one({"_id": uid}, {'file_name': 1})
        if result is None:
            result = self.file_objects.find_one({"_id": uid}, {'file_name': 1})
        return result['file_name'] if result is not None else None

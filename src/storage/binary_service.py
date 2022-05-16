import logging
from pathlib import Path
from typing import Optional, Tuple

from common_helper_files.fail_safe_file_operations import get_binary_from_file

from storage.db_interface_base import ReadOnlyDbInterface
from storage.fsorganizer import FSOrganizer
from storage.schema import FileObjectEntry
from unpacker.tar_repack import TarRepack


class BinaryService:
    '''
    This is a binary and database backend providing basic return functions
    '''

    def __init__(self, config=None):
        self.config = config
        self.fs_organizer = FSOrganizer(config=config)
        self.db_interface = BinaryServiceDbInterface(config=config)
        logging.info('binary service online')

    def get_binary_and_file_name(self, uid: str) -> Tuple[Optional[bytes], Optional[str]]:
        file_name = self.db_interface.get_file_name(uid)
        if file_name is None:
            return None, None
        binary = get_binary_from_file(self.fs_organizer.generate_path_from_uid(uid))
        return binary, file_name

    def read_partial_binary(self, uid: str, offset: int, length: int) -> bytes:
        file_name = self.db_interface.get_file_name(uid)
        if file_name is None:
            logging.error(f'[BinaryService]: Tried to read from file {uid} but it was not found.')
            return b''
        file_path = Path(self.fs_organizer.generate_path_from_uid(uid))
        with file_path.open('rb') as fp:
            fp.seek(offset)
            return fp.read(length)

    def get_repacked_binary_and_file_name(self, uid: str) -> Tuple[Optional[bytes], Optional[str]]:
        file_name = self.db_interface.get_file_name(uid)
        if file_name is None:
            return None, None
        repack_service = TarRepack()
        tar = repack_service.tar_repack(self.fs_organizer.generate_path_from_uid(uid))
        name = f'{file_name}.tar.gz'
        return tar, name


class BinaryServiceDbInterface(ReadOnlyDbInterface):
    def get_file_name(self, uid: str) -> Optional[str]:
        with self.get_read_only_session() as session:
            entry: FileObjectEntry = session.get(FileObjectEntry, uid)
            return entry.file_name if entry is not None else None

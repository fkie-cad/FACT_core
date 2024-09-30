from __future__ import annotations

import logging
from io import BytesIO
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from common_helper_files.fail_safe_file_operations import get_binary_from_file

from storage.db_interface_base import ReadOnlyDbInterface
from storage.fsorganizer import FSOrganizer
from storage.schema import FileObjectEntry
from unpacker.tar_repack import TarRepack


class BinaryService:
    """
    This is a binary and database backend providing basic return functions
    """

    def __init__(self):
        self.fs_organizer = FSOrganizer()
        self.db_interface = BinaryServiceDbInterface()

    def get_binary_and_file_name(self, uid: str) -> tuple[bytes | None, str | None]:
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

    def get_repacked_binary_and_file_name(self, uid: str) -> tuple[bytes | None, str | None]:
        file_name = self.db_interface.get_file_name(uid)
        if file_name is None:
            return None, None
        repack_service = TarRepack()
        tar = repack_service.tar_repack(self.fs_organizer.generate_path_from_uid(uid))
        name = f'{file_name}.tar.gz'
        return tar, name

    def get_files_as_zip(self, uid_list: list[str]) -> bytes:
        """Zips files in memory and returns the whole shebang as byte string"""
        with BytesIO() as buffer:
            with ZipFile(buffer, 'w', ZIP_DEFLATED) as zip_file:
                for uid in uid_list:
                    file_path = self.fs_organizer.generate_path_from_uid(uid)
                    zip_file.writestr(f'files/{uid}', Path(file_path).read_bytes())
            return buffer.getvalue()


class BinaryServiceDbInterface(ReadOnlyDbInterface):
    def get_file_name(self, uid: str) -> str | None:
        with self.get_read_only_session() as session:
            entry: FileObjectEntry = session.get(FileObjectEntry, uid)
            return entry.file_name if entry is not None else None

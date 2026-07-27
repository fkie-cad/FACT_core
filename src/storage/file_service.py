from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING

from common_helper_files import delete_file, write_binary_to_file

import config
from helperFunctions.uid import create_uid
from unpacker.tar_repack import TarRepack

if TYPE_CHECKING:
    from objects.file import FileObject


class FileService:
    """
    This module handles loading, storing and deleting files to and from the file system. It also creates and retrieves
    the file system path for a given UID of a FileObject.
    """

    def __init__(self):
        self.data_storage_path = Path(config.backend.firmware_file_storage_directory).absolute()
        self.data_storage_path.parent.mkdir(parents=True, exist_ok=True)

    def store_file(self, contents: bytes, uid: str | None = None) -> None:
        if uid is None:
            uid = create_uid(contents)
        destination_path = self.generate_path_from_uid(uid)
        write_binary_to_file(contents, destination_path, overwrite=False)

    def move_file_to_storage(self, path: Path, uid: str) -> None:
        """
        Move an existing file to the storage path. If the file already exists in the file system, this is more
        efficient than writing a new file and deleting the old one.
        """
        destination_path = self.generate_path_from_uid(uid)
        destination_path.parent.mkdir(exist_ok=True)
        path.replace(destination_path)

    def delete_file(self, uid: str) -> None:
        local_file_path = self.generate_path_from_uid(uid)
        delete_file(local_file_path)

    def generate_path(self, file_object: FileObject) -> Path:
        return self.generate_path_from_uid(file_object.uid)

    def generate_path_from_uid(self, uid: str) -> Path:
        return self.data_storage_path / uid[0:2] / uid

    def get_file_content(self, file_object: FileObject) -> bytes | None:
        return self.get_file_content_from_uid(file_object.uid)

    def get_file_content_from_uid(self, uid: str) -> bytes | None:
        file_path = self.generate_path_from_uid(uid)
        if not file_path.is_file():
            return None
        return file_path.read_bytes()

    def get_partial_file_content(self, uid: str, offset: int, length: int) -> bytes:
        file_path = Path(self.generate_path_from_uid(uid))
        if not file_path.is_file():
            logging.error(f'[FileService]: Tried to read from file {uid} but it was not found.')
            return b''
        with file_path.open('rb') as fp:
            fp.seek(offset)
            return fp.read(length)

    def get_repacked_file_as_bytes(self, uid: str) -> bytes | None:
        repack_service = TarRepack()
        file_path = self.generate_path_from_uid(uid)
        if not file_path.is_file():
            return None
        return repack_service.tar_repack(file_path)

from __future__ import annotations

import logging
import os
import tarfile
import time
from base64 import b64encode
from itertools import pairwise, product
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path
    from typing import BinaryIO

    from storage.db_interface_common import DbInterfaceCommon
    from storage.file_service import FileService

SYMLINK_MIME = 'inode/symlink'
# files that get the executable bit if their container has no file_system_metadata result for them
EXECUTABLE_MIME_TYPES = {'application/x-executable', 'application/x-pie-executable', 'application/x-sharedlib'}
EXECUTABLE_MODE = 0o755
DEFAULT_MODE = 0o644


class TarPacker:
    """
    Packs the files extracted from a file (one layer) or from a whole firmware (all layers) into a .tar.gz archive,
    taking the files from the file storage and their paths from the database. Files get their original modes from the
    `file_system_metadata` result of their container if it has one for them (e.g. for file systems that the plugin can
    mount), otherwise 0755 for executables, shared libraries and scripts and 0644 for all other files. Stored symbolic
    links become symbolic links again.
    """

    def __init__(self, db: DbInterfaceCommon, file_service: FileService):
        self.db = db
        self.file_service = file_service

    def pack_included_files(self, parent_uid: str, output: BinaryIO) -> None:
        vfp_dict = self.db.get_vfps_in_parent(parent_uid)
        mime_types = self._get_mime_types(vfp_dict)
        modes = self._get_original_modes([parent_uid])

        with tarfile.open(fileobj=output, mode='w:gz') as tar:
            for uid, path_list in vfp_dict.items():
                for path in path_list:
                    original_mode = modes.get(parent_uid, {}).get(_get_metadata_key(path))
                    self._add_file(tar, path, uid, mime_types.get(uid), original_mode)

    def pack_included_files_recursively(self, fw_uid: str, output: BinaryIO) -> None:
        if not self.db.is_firmware(fw_uid):
            raise RuntimeError(f'FW with UID {fw_uid} not found')
        all_files = self.db.get_all_files_in_fw(fw_uid)
        file_tree_paths = self.db.get_file_tree_path_for_uid_list(root_uid=fw_uid, uid_list=list(all_files))
        vfps = self.db.get_vfps_for_uid_list(all_files)
        mime_types = self._get_mime_types(all_files)
        modes = self._get_original_modes({tree_path[-2] for paths in file_tree_paths.values() for tree_path in paths})

        with tarfile.open(fileobj=output, mode='w:gz') as tar:
            for uid, file_tree_path_list in file_tree_paths.items():
                for file_tree_path in file_tree_path_list:
                    container_modes = modes.get(file_tree_path[-2], {})
                    path_elements = []
                    for parent_uid, child_uid in pairwise(file_tree_path):
                        vfp_list = vfps.get(child_uid, {}).get(parent_uid, [])
                        path_elements.append(vfp_list)
                    for path_list in product(*path_elements):
                        path = ''
                        for path_element in path_list[:-1]:
                            path += path_element.strip('/') + '_extracted/'
                        path += path_list[-1].strip('/')
                        original_mode = container_modes.get(_get_metadata_key(path_list[-1]))
                        self._add_file(tar, path, uid, mime_types.get(uid), original_mode)

    def _get_mime_types(self, uid_list: list[str] | set[str] | dict[str, list[str]]) -> dict[str, str | None]:
        results = self.db.get_analysis_results_for_uid_list(uid_list, 'file_type')
        return {uid: result.get('mime') for uid, result in results.items()}

    def _get_original_modes(self, container_uids: list[str] | set[str]) -> dict[str, dict[str, int]]:
        """:return: the permission bits of the files in each container per metadata key (if the container has any)"""
        results = self.db.get_analysis_results_for_uid_list(container_uids, 'file_system_metadata')
        return {
            uid: {
                metadata['key']: int(metadata['mode'], 8) & 0o7777
                for metadata in result.get('files', [])
                if 'key' in metadata and 'mode' in metadata
            }
            for uid, result in results.items()
        }

    def _add_file(self, tar: tarfile.TarFile, path: str, uid: str, mime: str | None, original_mode: int | None) -> None:
        system_path = self.file_service.generate_path_from_uid(uid)
        if mime == SYMLINK_MIME:
            # stored by the unpacker as `symbolic link -> <target>` (see unpacker/unpack.py)
            link_target = system_path.read_text().removeprefix('symbolic link -> ')
            logging.debug(f'Adding file {path} as symlink to {link_target}')
            tar.addfile(self._create_symlink(path, link_target))
            return
        logging.debug(f'Adding file {path} from {system_path}')
        info = tar.gettarinfo(system_path, arcname=path)
        info.mode = original_mode if original_mode is not None else _get_default_mode(system_path, mime)
        with system_path.open('rb') as file:
            tar.addfile(info, file)

    @staticmethod
    def _create_symlink(path: str, link_target: str) -> tarfile.TarInfo:
        info = tarfile.TarInfo(name=path.strip('/'))
        info.type = tarfile.SYMTYPE
        info.linkname = link_target
        info.uid = os.getuid()
        info.gid = os.getgid()
        info.mtime = time.time()
        info.mode = 0o777
        return info


def _get_metadata_key(path: str) -> str:
    """:return: the key of the file at `path` in the `file_system_metadata` result of its container"""
    return b64encode(path.lstrip('/').encode()).decode()


def _get_default_mode(system_path: Path, mime: str | None) -> int:
    if mime in EXECUTABLE_MIME_TYPES:
        return EXECUTABLE_MODE
    with system_path.open('rb') as file:
        is_script = file.read(2) == b'#!'
    return EXECUTABLE_MODE if is_script else DEFAULT_MODE

from __future__ import annotations

import logging
import os
import tarfile
import time
from itertools import pairwise, product
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from storage.db_interface_common import DbInterfaceCommon
    from storage.file_service import FileService


class TarPacker:
    def __init__(self, db: DbInterfaceCommon, file_service: FileService):
        self.db = db
        self.file_service = file_service

    def pack_included_files(self, parent_uid: str, output_file: str) -> None:
        vfp_dict = self.db.get_vfps_in_parent(parent_uid)
        symlinks = set(self.db.get_all_files_of_type_in_fo(parent_uid, 'inode/symlink'))

        with tarfile.open(output_file, 'w:gz') as tar:
            for uid, path_list in vfp_dict.items():
                system_path = self.file_service.generate_path_from_uid(uid)
                self._add_files_to_tar(path_list, system_path, tar, uid in symlinks)

    def pack_included_files_recursively(self, fw_uid: str, output_file: str) -> None:
        if not self.db.is_firmware(fw_uid):
            raise RuntimeError(f'FW with UID {fw_uid} not found')
        all_files = self.db.get_all_files_in_fw(fw_uid)
        file_tree_paths = self.db.get_file_tree_path_for_uid_list(root_uid=fw_uid, uid_list=list(all_files))
        vfps = self.db.get_vfps_for_uid_list(all_files)
        symlinks = set(self.db.get_all_files_of_type_in_fw(fw_uid, 'inode/symlink'))

        with tarfile.open(output_file, 'w:gz') as tar:
            for uid, file_tree_path_list in file_tree_paths.items():
                system_path = self.file_service.generate_path_from_uid(uid)
                for file_tree_path in file_tree_path_list:
                    path_elements = []
                    for parent_uid, child_uid in pairwise(file_tree_path):
                        vfp_list = vfps.get(child_uid, {}).get(parent_uid, [])
                        path_elements.append(vfp_list)
                    paths = []
                    for path_list in product(*path_elements):
                        path = ''
                        for path_element in path_list[:-1]:
                            path += f'{_normalize_path(path_element)}_extracted/'
                        path += _normalize_path(path_list[-1])
                        paths.append(path)

                    self._add_files_to_tar(paths, system_path, tar, uid in symlinks)

    @classmethod
    def _add_files_to_tar(cls, paths: list[str], system_path: Path, tar: tarfile.TarFile, is_symlink: bool) -> None:
        if is_symlink:
            link_target = system_path.read_text().split(' ')[-1]
            for path in paths:
                logging.debug(f'Adding file {path} as symlink to {link_target}')
                tar.addfile(cls._create_symlink(path, link_target))
        else:
            for path in paths:
                logging.debug(f'Adding file {path} from {system_path}')
                tar.add(system_path, arcname=path)

    @staticmethod
    def _create_symlink(path: str, link_target: str) -> tarfile.TarInfo:
        info = tarfile.TarInfo(name=path.lstrip('/').rstrip('/'))
        info.type = tarfile.SYMTYPE
        info.linkname = link_target
        info.uid = os.getuid()
        info.gid = os.getgid()
        info.mtime = time.time()
        info.mode = 0o777
        return info


def _normalize_path(path: str) -> str:
    return path.lstrip('/').rstrip('/')

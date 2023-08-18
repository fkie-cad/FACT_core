from __future__ import annotations

import json
import logging
import stat
import tarfile
import zlib
from base64 import b64encode
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import NamedTuple, TYPE_CHECKING

from docker.types import Mount

import config
from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.docker import run_docker_container
from helperFunctions.tag import TagColor
from storage.db_interface_common import DbInterfaceCommon

if TYPE_CHECKING:
    from objects.file import FileObject

DOCKER_IMAGE = 'fact/fs_metadata:latest'
SUID_BIT = 0b100 << 9
SGID_BIT = 0b010 << 9
STICKY_BIT = 0b001 << 9


class StatResult(NamedTuple):
    uid: int
    gid: int
    mode: int
    a_time: float
    c_time: float
    m_time: float


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'file_system_metadata'
    DEPENDENCIES = ['file_type']  # noqa: RUF012
    DESCRIPTION = 'extract file system metadata (e.g. owner, group, etc.) from file system images contained in firmware'
    VERSION = '0.2.1'
    TIMEOUT = 600
    FILE = __file__

    ARCHIVE_MIME_TYPES = [  # noqa: RUF012
        'application/gzip',
        'application/x-bzip2',
        'application/x-tar',
    ]
    FS_MIME_TYPES = [  # noqa: RUF012
        'filesystem/btrfs',
        'filesystem/cramfs',
        'filesystem/dosmbr',
        'filesystem/ext2',
        'filesystem/ext3',
        'filesystem/ext4',
        'filesystem/hfs',
        'filesystem/jfs',
        'filesystem/minix',
        'filesystem/reiserfs',
        'filesystem/romfs',
        'filesystem/udf',
        'filesystem/xfs',
        'filesystem/squashfs',
    ]

    def __init__(self, *args, **kwargs):
        self.db = DbInterfaceCommon()
        super().__init__(*args, **kwargs)

    def process_object(self, file_object: FileObject) -> FileObject:
        result = self._extract_metadata(file_object)
        if 'files' in result:
            self._add_tag(file_object, result['files'])
        result['contained_in_file_system'] = self._parent_has_file_system_metadata(file_object)
        file_object.processed_analysis[self.NAME] = result
        return file_object

    def _parent_has_file_system_metadata(self, file_object: FileObject) -> bool:
        if hasattr(file_object, 'temporary_data') and 'parent_fo_type' in file_object.temporary_data:
            return self._has_correct_type(file_object.temporary_data['parent_fo_type'])
        return self._parent_fo_has_results(file_object)

    def _parent_fo_has_results(self, file_object: FileObject) -> bool:
        for parent_uid in file_object.parents:
            analysis_entry = self.db.get_analysis(parent_uid, 'file_type')
            if analysis_entry is not None and self._has_correct_type(analysis_entry['result']['mime']):
                return True
        return False

    def _has_correct_type(self, mime_type: str) -> bool:
        return mime_type in self.ARCHIVE_MIME_TYPES + self.FS_MIME_TYPES

    def _extract_metadata(self, file_object: FileObject) -> dict:
        file_type = file_object.processed_analysis['file_type']['result']['mime']
        if file_type in self.FS_MIME_TYPES:
            return self._extract_metadata_from_file_system(file_object)
        if file_type in self.ARCHIVE_MIME_TYPES:
            return self._extract_metadata_from_tar(file_object)
        return {}

    def _extract_metadata_from_file_system(self, file_object: FileObject) -> dict:
        with TemporaryDirectory(dir=config.backend.docker_mount_base_dir) as tmp_dir:
            input_file = Path(tmp_dir) / 'input.img'
            input_file.write_bytes(file_object.binary)  # type: ignore[arg-type]  # we assume that binary is set
            output = self._mount_in_docker(tmp_dir)
            output_file = Path(tmp_dir) / 'output.pickle'
            if output_file.is_file():
                metadata = self._analyze_metadata_of_mounted_dir(json.loads(output_file.read_bytes()))
                if metadata:
                    return {'files': metadata}
                return {}
            message = f'mount failed:\n{output}'
            logging.warning(f'[file_system_metadata] {message}')
            return {'failed': message}

    def _mount_in_docker(self, input_dir: str) -> str:
        result = run_docker_container(
            DOCKER_IMAGE,
            combine_stderr_stdout=True,
            logging_label=self.NAME,
            mounts=[
                Mount('/work', input_dir, type='bind'),
            ],
            timeout=int(self.TIMEOUT * 0.8),  # docker call gets 80% of the analysis time before it times out
            privileged=True,
        )

        return result.stdout

    def _analyze_metadata_of_mounted_dir(self, docker_results: tuple[str, str, dict]) -> dict[str, dict]:
        result = {}
        for file_name, file_path, file_stats in docker_results:
            result.update(self._get_results_for_mounted_file(file_name, file_path, StatResult(**file_stats)))
        return result

    def _get_results_for_mounted_file(self, file_name: str, file_path: str, stats: StatResult):
        file_mode = self._get_mounted_file_mode(stats)
        result = {
            FsKeys.MODE: file_mode,
            FsKeys.MODE_HR: stat.filemode(stats.mode),
            FsKeys.NAME: file_name,
            FsKeys.PATH: file_path,
            FsKeys.UID: stats.uid,
            FsKeys.GID: stats.gid,
            FsKeys.USER: 'root' if stats.uid == 0 else '',
            FsKeys.GROUP: 'root' if stats.gid == 0 else '',
            FsKeys.M_TIME: stats.m_time,
            FsKeys.A_TIME: stats.a_time,
            FsKeys.C_TIME: stats.c_time,
            FsKeys.SUID: self._file_mode_contains_bit(file_mode, SUID_BIT),
            FsKeys.SGID: self._file_mode_contains_bit(file_mode, SGID_BIT),
            FsKeys.STICKY: self._file_mode_contains_bit(file_mode, STICKY_BIT),
        }
        key = b64encode(file_name.encode()).decode()
        return {key: result}

    def _extract_metadata_from_tar(self, file_object: FileObject) -> dict[str, dict]:
        metadata = {}
        try:
            with tarfile.open(file_object.file_path) as tar_archive:
                for file_info in tar_archive:
                    if file_info.isfile():
                        metadata.update(self._get_results_for_tar_file(file_info))
        except (tarfile.TarError, zlib.error, EOFError) as error:
            logging.warning(f'[{self.NAME}]: Could not open archive on {file_object.uid}: {error}', exc_info=True)
        if metadata:
            return {'files': metadata}
        return {}

    def _get_results_for_tar_file(self, file_info: tarfile.TarInfo) -> dict[str, dict]:
        file_path = file_info.name
        if file_path[:2] == './':
            file_path = file_path[2:]
        file_mode = self._get_tar_file_mode_str(file_info)
        result = {
            FsKeys.MODE: file_mode,
            FsKeys.NAME: Path(file_path).name,
            FsKeys.PATH: file_path,
            FsKeys.USER: file_info.uname,
            FsKeys.GROUP: file_info.gname,
            FsKeys.UID: file_info.uid,
            FsKeys.GID: file_info.gid,
            FsKeys.M_TIME: file_info.mtime,
            FsKeys.SUID: self._file_mode_contains_bit(file_mode, SUID_BIT),
            FsKeys.SGID: self._file_mode_contains_bit(file_mode, SGID_BIT),
            FsKeys.STICKY: self._file_mode_contains_bit(file_mode, STICKY_BIT),
        }
        key = b64encode(file_path.encode()).decode()
        return {key: result}

    @staticmethod
    def _file_mode_contains_bit(file_mode: str, bit: int) -> bool:
        return bool(int(file_mode, 8) & bit)

    @staticmethod
    def _get_mounted_file_mode(stats: StatResult):
        return oct(stat.S_IMODE(stats.mode))[2:]

    @staticmethod
    def _get_tar_file_mode_str(file_info: tarfile.TarInfo) -> str:
        return oct(file_info.mode)[2:]

    def _add_tag(self, file_object: FileObject, results: dict):
        if self._tag_should_be_set(results):
            self.add_analysis_tag(
                file_object=file_object,
                tag_name='SUID/GUID + root',
                value='SUID/GUID + root',
                color=TagColor.BLUE,
                propagate=False,
            )

    @staticmethod
    def _tag_should_be_set(results: dict):
        return any(
            result[FsKeys.USER] == 'root' and (result[FsKeys.SUID] or result[FsKeys.SGID])
            for result in results.values()
            if FsKeys.USER in result
        )


class FsKeys:
    MODE = 'file mode octal'
    MODE_HR = 'file mode'
    NAME = 'file name'
    PATH = 'file path'
    UID = 'owner user id'
    GID = 'owner group id'
    USER = 'owner'
    GROUP = 'owner group'
    M_TIME = 'modification time'
    A_TIME = 'access time'
    C_TIME = 'creation time'
    SUID = 'setuid flag'
    SGID = 'setgid flag'
    STICKY = 'sticky flag'

from __future__ import annotations

import json
import logging
import re
import stat
import tarfile
import zlib
from base64 import b64encode
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING, List, NamedTuple, Optional

from docker.types import Mount
from pydantic import BaseModel, Field

import config
from analysis.plugin import AnalysisPluginV0, Tag
from analysis.plugin.compat import AnalysisBasePluginAdapterMixin
from helperFunctions.docker import run_docker_container
from helperFunctions.tag import TagColor

if TYPE_CHECKING:
    from io import FileIO

DOCKER_IMAGE = 'fact/fs_metadata:latest'
SUID_BIT = 0b100 << 9
SGID_BIT = 0b010 << 9
STICKY_BIT = 0b001 << 9
ARCHIVE_MIME_TYPES = [
    'application/gzip',
    'application/x-bzip2',
    'application/x-tar',
]
FS_MIME_TYPES = [
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
YAFFS_REGEX = re.compile(r'([rwxtTsSl?-]{10}) +\d+ (\d{4}-\d{2}-\d{2} \d{2}:\d{2}) ([^\n]+)')
REVERSE_FILEMODE_LOOKUP = [{char: mode for mode, char in row} for row in stat._filemode_table]


class StatResult(NamedTuple):
    uid: int
    gid: int
    mode: int
    a_time: float
    c_time: float
    m_time: float


class FileMetadata(BaseModel):
    mode: str = Field(
        description="The file's permissions as octal number",
    )
    name: str = Field(
        description="The file's name",
    )
    path: str = Field(
        description="The file's path",
    )
    user: Optional[str] = Field(
        default=None,
        description="The user name of the file's owner",
    )
    uid: Optional[int] = Field(
        default=None,
        description="The user ID of the file's owner",
    )
    group: Optional[str] = Field(
        default=None,
        description="The group name of the file's owner",
    )
    gid: Optional[int] = Field(
        default=None,
        description="The group ID of the file's owner",
    )
    modification_time: float = Field(
        description="The time of the file's last modification (as UNIX timestamp)",
    )
    access_time: Optional[float] = Field(
        None,
        description="The time of the file's last access (as UNIX timestamp)",
    )
    creation_time: Optional[float] = Field(
        None,
        description="The time of the file's creation (as UNIX timestamp)",
    )
    suid_bit: bool = Field(
        description='Whether the Setuid bit is set for this file',
    )
    sgid_bit: bool = Field(
        description='Whether the Setgid bit is set for this file',
    )
    sticky_bit: bool = Field(
        description='Whether the sticky bit is set for this file',
    )
    key: str = Field(
        description='Used internally for matching this file in the parent container',
    )


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    NAME = 'file_system_metadata'

    class Schema(BaseModel):
        files: List[FileMetadata] = Field(
            description='An array of metadata objects (each representing the results of a contained file)',
        )

    def __init__(self):
        metadata = self.MetaData(
            name=self.NAME,
            dependencies=['file_type'],
            description=(
                'extract file system metadata (e.g. owner, group, etc.) from file system images contained in firmware'
            ),
            version='1.1.0',
            Schema=self.Schema,
            timeout=30,
        )
        super().__init__(metadata=metadata)

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel | dict]) -> Schema:
        del virtual_file_path
        file_type = analyses['file_type'].mime
        result = self._extract_metadata(file_handle, file_type, analyses)
        return self.Schema(files=result)

    def _extract_metadata(
        self, file_handle: FileIO, file_type: str, analyses: dict[str, BaseModel | dict]
    ) -> list[FileMetadata]:
        if file_type in FS_MIME_TYPES:
            return self._extract_metadata_from_file_system(file_handle)
        if file_type in ARCHIVE_MIME_TYPES:
            return _extract_metadata_from_tar(file_handle)
        if file_type == 'filesystem/yaffs':
            return self._extract_metadata_from_yaffs(analyses)
        return []

    def _extract_metadata_from_yaffs(self, analyses: dict[str, BaseModel | dict]) -> list[FileMetadata]:
        result = []
        unpacker_result = analyses.get('unpacker')
        if not isinstance(unpacker_result, dict) or unpacker_result['plugin_used'] != 'YAFFS':
            return result
        """
        the output of unyaffs from the unpacker log has the following structure:
        brw-r-----  31,   4 2014-07-19 01:28 dev/mtdblock4
        -rw-r--r--       38 2014-07-19 01:31 build.prop
        drwxr-xr-x        0 2016-10-11 03:12 sbin
        lrwxrwxrwx        0 2014-07-19 01:28 sbin/ifconfig -> ../bin/busybox
        we ignore directories and block devices
        """
        for match in YAFFS_REGEX.finditer(unpacker_result['output']):
            mode_str, date, path = match.groups()
            mode = oct(_filemode_str_to_int(mode_str))
            if '->' in path:
                # symlink entries have a " -> [target]" after their path (see comment above)
                path = path.split('->')[0].strip()
            result.append(
                FileMetadata(
                    mode=mode,
                    name=Path(path).name,
                    path=f'/{path}',
                    modification_time=datetime.fromisoformat(date).timestamp(),
                    suid_bit=_file_mode_contains_bit(mode, SUID_BIT),
                    sgid_bit=_file_mode_contains_bit(mode, SGID_BIT),
                    sticky_bit=_file_mode_contains_bit(mode, STICKY_BIT),
                    key=b64encode(path.encode()).decode(),
                )
            )
        return result

    def _extract_metadata_from_file_system(self, file_handle: FileIO) -> list[FileMetadata]:
        with TemporaryDirectory(dir=config.backend.docker_mount_base_dir) as tmp_dir:
            input_file = Path(tmp_dir) / 'input.img'
            input_file.write_bytes(file_handle.readall())
            output = self._mount_in_docker(tmp_dir)
            output_file = Path(tmp_dir) / 'output.pickle'
            if output_file.is_file():
                return _analyze_metadata_of_mounted_dir(json.loads(output_file.read_bytes()))
            message = 'Mounting the file system failed'
            logging.warning(f'{message} for {file_handle.name}:\n{output}')
            raise RuntimeError(message)

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

    def summarize(self, result: Schema) -> list[str]:
        summary = set()
        for file_metadata in result.files:
            if file_metadata.suid_bit:
                summary.add('SUID bit')
            if file_metadata.sgid_bit:
                summary.add('SGID bit')
        return list(summary)

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del summary
        if not _tag_should_be_set(result):
            return []
        return [
            Tag(
                name=self.metadata.name,
                value='SUID/GUID + root',
                color=TagColor.BLUE,
                propagate=False,
            )
        ]


def _tag_should_be_set(result: AnalysisPlugin.Schema) -> bool:
    return any(
        file_metadata.user == 'root' and (file_metadata.suid_bit or file_metadata.sgid_bit)
        for file_metadata in result.files
    )


def _analyze_metadata_of_mounted_dir(docker_results: tuple[str, str, dict]) -> list[FileMetadata]:
    return [
        _get_results_for_mounted_file(file_name, file_path, StatResult(**file_stats))
        for file_name, file_path, file_stats in docker_results
    ]


def _get_results_for_mounted_file(file_name: str, file_path: str, stats: StatResult) -> FileMetadata:
    file_mode = _get_mounted_file_mode(stats)
    return FileMetadata(
        mode=file_mode,
        name=file_name,
        path=file_path,
        uid=stats.uid,
        gid=stats.gid,
        user='root' if stats.uid == 0 else '',
        group='root' if stats.gid == 0 else '',
        modification_time=stats.m_time,
        access_time=stats.a_time,
        creation_time=stats.c_time,
        suid_bit=_file_mode_contains_bit(file_mode, SUID_BIT),
        sgid_bit=_file_mode_contains_bit(file_mode, SGID_BIT),
        sticky_bit=_file_mode_contains_bit(file_mode, STICKY_BIT),
        key=b64encode(file_path.encode()).decode(),
    )


def _extract_metadata_from_tar(file_handle: FileIO) -> list[FileMetadata]:
    result = []
    try:
        with tarfile.open(file_handle.name) as tar_archive:
            for file_info in tar_archive:
                if file_info.isfile():
                    result.append(_get_results_for_tar_file(file_info))
    except EOFError:
        logging.warning(f'File {file_handle.name} ended unexpectedly')
    except (tarfile.TarError, zlib.error, tarfile.ReadError) as error:
        raise RuntimeError('Could not open tar archive') from error
    return result


def _get_results_for_tar_file(file_info: tarfile.TarInfo) -> FileMetadata:
    file_path = file_info.name
    if file_path[:2] == './':
        file_path = file_path[2:]
    file_mode = _get_tar_file_mode_str(file_info)
    return FileMetadata(
        mode=file_mode,
        name=Path(file_path).name,
        path=file_path,
        user=file_info.uname,
        group=file_info.gname,
        uid=file_info.uid,
        gid=file_info.gid,
        modification_time=file_info.mtime,
        suid_bit=_file_mode_contains_bit(file_mode, SUID_BIT),
        sgid_bit=_file_mode_contains_bit(file_mode, SGID_BIT),
        sticky_bit=_file_mode_contains_bit(file_mode, STICKY_BIT),
        key=b64encode(file_path.encode()).decode(),
    )


def _file_mode_contains_bit(file_mode: str, bit: int) -> bool:
    return bool(int(file_mode, 8) & bit)


def _get_mounted_file_mode(stats: StatResult) -> str:
    return oct(stat.S_IMODE(stats.mode))[2:]


def _get_tar_file_mode_str(file_info: tarfile.TarInfo) -> str:
    return oct(file_info.mode)[2:]


def _has_correct_type(mime_type: str) -> bool:
    return mime_type in ARCHIVE_MIME_TYPES + FS_MIME_TYPES


def _filemode_str_to_int(filemode: str) -> int:
    result = 0
    for char, lookup in zip(filemode, REVERSE_FILEMODE_LOOKUP):
        result += lookup.get(char, 0)
    return result

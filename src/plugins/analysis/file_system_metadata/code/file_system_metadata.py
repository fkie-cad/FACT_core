import json
import logging
import stat
import tarfile
import zlib
from base64 import b64encode
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, NamedTuple, Tuple

from docker.types import Mount

from analysis.PluginBase import AnalysisBasePlugin
from config import cfg, configparser_cfg
from helperFunctions.docker import run_docker_container
from helperFunctions.tag import TagColor
from helperFunctions.virtual_file_path import get_parent_uids_from_virtual_path
from objects.file import FileObject
from storage.db_interface_common import DbInterfaceCommon

DOCKER_IMAGE = 'fact/fs_metadata:latest'
StatResult = NamedTuple(
    'StatEntry',
    [('uid', int), ('gid', int), ('mode', int), ('a_time', float), ('c_time', float), ('m_time', float)]
)


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'file_system_metadata'
    DEPENDENCIES = ['file_type']
    DESCRIPTION = 'extract file system metadata (e.g. owner, group, etc.) from file system images contained in firmware'
    VERSION = '0.2.1'
    TIMEOUT = 600
    FILE = __file__

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
        'filesystem/squashfs'
    ]

    def __init__(self, *args, db_interface=None, **kwargs):
        self.db = db_interface if db_interface is not None else DbInterfaceCommon(config=configparser_cfg)
        self.result = None
        super().__init__(*args, **kwargs)

    def process_object(self, file_object: FileObject) -> FileObject:
        self.result = {}
        self._extract_metadata(file_object)
        self._set_result_propagation_flag(file_object)
        return file_object

    def _set_result_propagation_flag(self, file_object: FileObject):
        if 'file_system_metadata' not in file_object.processed_analysis:
            file_object.processed_analysis['file_system_metadata'] = {}
        file_object.processed_analysis['file_system_metadata']['contained_in_file_system'] = self._parent_has_file_system_metadata(file_object)

    def _parent_has_file_system_metadata(self, file_object: FileObject) -> bool:
        if hasattr(file_object, 'temporary_data') and 'parent_fo_type' in file_object.temporary_data:
            return self._has_correct_type(file_object.temporary_data['parent_fo_type'])
        return self.parent_fo_has_fs_metadata_analysis_results(file_object)

    def parent_fo_has_fs_metadata_analysis_results(self, file_object: FileObject):
        for parent_uid in get_parent_uids_from_virtual_path(file_object):
            analysis_entry = self.db.get_analysis(parent_uid, 'file_type')
            if analysis_entry is not None:
                if self._has_correct_type(analysis_entry['mime']):
                    return True
        return False

    def _has_correct_type(self, mime_type: str) -> bool:
        return mime_type in self.ARCHIVE_MIME_TYPES + self.FS_MIME_TYPES

    def _extract_metadata(self, file_object: FileObject):
        file_type = file_object.processed_analysis['file_type']['mime']
        if file_type in self.FS_MIME_TYPES:
            self._extract_metadata_from_file_system(file_object)
        elif file_type in self.ARCHIVE_MIME_TYPES:
            self._extract_metadata_from_tar(file_object)
        if self.result:
            file_object.processed_analysis[self.NAME] = {'files': self.result}
            self._add_tag(file_object, self.result)

    def _extract_metadata_from_file_system(self, file_object: FileObject):
        with TemporaryDirectory(dir=cfg.data_storage.docker_mount_base_dir) as tmp_dir:
            input_file = Path(tmp_dir) / 'input.img'
            input_file.write_bytes(file_object.binary or Path(file_object.file_path).read_bytes())
            output = self._mount_in_docker(tmp_dir)
            output_file = Path(tmp_dir) / 'output.pickle'
            if output_file.is_file():
                self._analyze_metadata_of_mounted_dir(json.loads(output_file.read_bytes()))
            else:
                message = f'mount failed:\n{output}'
                logging.warning(f'[file_system_metadata] {message}')
                file_object.processed_analysis[self.NAME]['failed'] = message

    def _mount_in_docker(self, input_dir: str) -> str:
        result = run_docker_container(
            DOCKER_IMAGE,
            combine_stderr_stdout=True,
            logging_label=self.NAME,
            mounts=[
                Mount('/work', input_dir, type='bind'),
            ],
            timeout=int(self.TIMEOUT * .8),  # docker call gets 80% of the analysis time before it times out
            privileged=True,
        )

        return result.stdout

    def _analyze_metadata_of_mounted_dir(self, docker_results: Tuple[str, str, dict]):
        for file_name, file_path, file_stats in docker_results:
            self._enter_results_for_mounted_file(file_name, file_path, StatResult(**file_stats))

    def _enter_results_for_mounted_file(self, file_name: str, file_path: str, stats: StatResult):
        result = self.result[b64encode(file_name.encode()).decode()] = {}
        result[FsKeys.MODE] = self._get_mounted_file_mode(stats)
        result[FsKeys.MODE_HR] = stat.filemode(stats.mode)
        result[FsKeys.NAME] = file_name
        result[FsKeys.PATH] = file_path
        result[FsKeys.UID] = stats.uid
        result[FsKeys.GID] = stats.gid
        result[FsKeys.USER] = 'root' if stats.uid == 0 else ''
        result[FsKeys.GROUP] = 'root' if stats.gid == 0 else ''
        result[FsKeys.M_TIME] = stats.m_time
        result[FsKeys.A_TIME] = stats.a_time
        result[FsKeys.C_TIME] = stats.c_time
        result[FsKeys.SUID], result[FsKeys.SGID], result[FsKeys.STICKY] = self._get_extended_file_permissions(result[FsKeys.MODE])

    def _extract_metadata_from_tar(self, file_object: FileObject):
        try:
            with tarfile.open(file_object.file_path) as tar_archive:
                for file_info in tar_archive:
                    if file_info.isfile():
                        self._enter_results_for_tar_file(file_info)
        except (tarfile.TarError, zlib.error, EOFError) as error:
            logging.warning(f'[{self.NAME}]: Could not open archive on {file_object.uid}: {error}', exc_info=True)

    def _enter_results_for_tar_file(self, file_info: tarfile.TarInfo):
        file_path = file_info.name
        if file_path[:2] == './':
            file_path = file_path[2:]
        result = self.result[b64encode(file_path.encode()).decode()] = {}
        result[FsKeys.MODE] = self._get_tar_file_mode_str(file_info)
        result[FsKeys.NAME] = Path(file_path).name
        result[FsKeys.PATH] = file_path
        result[FsKeys.USER] = file_info.uname
        result[FsKeys.GROUP] = file_info.gname
        result[FsKeys.UID] = file_info.uid
        result[FsKeys.GID] = file_info.gid
        result[FsKeys.M_TIME] = file_info.mtime
        result[FsKeys.SUID], result[FsKeys.SGID], result[FsKeys.STICKY] = self._get_extended_file_permissions(result[FsKeys.MODE])

    @staticmethod
    def _get_extended_file_permissions(file_mode: str) -> List[bool]:
        extended_file_permission_bits = f'{int(file_mode[-4]):03b}' if len(file_mode) > 3 else '000'
        return [b == '1' for b in extended_file_permission_bits]

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
                propagate=False
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

import logging
import os
import stat
import tarfile
import zlib
from base64 import b64encode
from contextlib import contextmanager, suppress
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List

from common_helper_files import safe_rglob
from common_helper_process import execute_shell_command, execute_shell_command_get_return_code

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.database import ConnectTo
from helperFunctions.tag import TagColor
from objects.file import FileObject
from storage.db_interface_common import MongoInterfaceCommon


class MountingError(RuntimeError):
    pass


@contextmanager
def mount(file_path, fs_type=''):
    mount_dir = TemporaryDirectory()
    try:
        mount_rv = execute_shell_command('sudo mount {} -v -o ro,loop {} {}'.format(fs_type, file_path, mount_dir.name))
        if _mount_was_successful(mount_dir.name):
            yield Path(mount_dir.name)
        else:
            logging.error('could not mount {}: {}'.format(file_path, mount_rv))
            raise MountingError('error while mounting fs')
    finally:
        execute_shell_command('sudo umount -v {}'.format(mount_dir.name))
        mount_dir.cleanup()


def _mount_was_successful(mount_path: str) -> bool:
    _, return_code = execute_shell_command_get_return_code('mountpoint {}'.format(mount_path))
    return return_code == 0


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'file_system_metadata'
    DEPENDENCIES = ['file_type']
    DESCRIPTION = 'extract file system metadata (e.g. owner, group, etc.) from file system images contained in firmware'
    VERSION = '0.1'

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

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.result = {}
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

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
            mime_type = file_object.temporary_data['parent_fo_type']
            return mime_type in self.ARCHIVE_MIME_TYPES + self.FS_MIME_TYPES
        with ConnectTo(FsMetadataDbInterface, self.config) as db_interface:
            return db_interface.parent_fo_has_fs_metadata_analysis_results(file_object)

    def _extract_metadata(self, file_object: FileObject):
        file_type = file_object.processed_analysis['file_type']['mime']
        if file_type in self.FS_MIME_TYPES:
            self._extract_metadata_from_file_system(file_object, file_type)
        elif file_type in self.ARCHIVE_MIME_TYPES:
            self._extract_metadata_from_tar(file_object)
        if self.result:
            file_object.processed_analysis['file_system_metadata'] = {'files': self.result}
            self._add_tag(file_object, self.result)

    def _extract_metadata_from_file_system(self, file_object: FileObject, file_type: str):
        type_parameter = '-t {}'.format(file_type.split('/')[1])
        with suppress(MountingError):
            with mount(file_object.file_path, type_parameter) as mounted_path:
                self._analyze_metadata_of_mounted_dir(mounted_path)

    def _analyze_metadata_of_mounted_dir(self, mounted_dir: Path):
        for file_ in safe_rglob(mounted_dir, False, False):  # FIXME files with PermissionError could be ignored
            if file_.is_file() and not file_.is_symlink():
                self._enter_results_for_mounted_file(file_)

    def _enter_results_for_mounted_file(self, file_: Path):
        result = self.result[b64encode(file_.name.encode()).decode()] = {}
        stats = os.lstat(str(file_))
        result[FsKeys.MODE] = self._get_mounted_file_mode(stats)
        result[FsKeys.MODE_HR] = stat.filemode(stats.st_mode)
        result[FsKeys.NAME] = file_.name
        result[FsKeys.PATH] = str(file_)
        result[FsKeys.UID] = stats.st_uid
        result[FsKeys.GID] = stats.st_gid
        result[FsKeys.USER] = 'root' if stats.st_uid == 0 else ''
        result[FsKeys.GROUP] = 'root' if stats.st_gid == 0 else ''
        result[FsKeys.M_TIME] = stats.st_mtime
        result[FsKeys.A_TIME] = stats.st_atime
        result[FsKeys.C_TIME] = stats.st_ctime
        result[FsKeys.SUID], result[FsKeys.SGID], result[FsKeys.STICKY] = self._get_extended_file_permissions(result[FsKeys.MODE])

    def _extract_metadata_from_tar(self, file_object: FileObject):
        try:
            for file_info in tarfile.open(file_object.file_path):
                if file_info.isfile():
                    self._enter_results_for_tar_file(file_info)
        except tarfile.TarError:
            logging.warning('could not open tar archive {}'.format(file_object.file_name))
        except zlib.error:
            logging.warning('could not open compressed tar archive: {}'.format(file_object.file_name))
        except EOFError:
            logging.warning('could not open archive: unexpected EOF {}'.format(file_object.file_name))

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
        extended_file_permission_bits = "{0:03b}".format(int(file_mode[-4])) if len(file_mode) > 3 else '000'
        return [b == '1' for b in extended_file_permission_bits]

    @staticmethod
    def _get_tar_file_mode_str(file_info: tarfile.TarInfo) -> str:
        return oct(file_info.mode)[2:]

    @staticmethod
    def _get_mounted_file_mode(stats):
        return oct(stat.S_IMODE(stats.st_mode))[2:]

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


class FsMetadataDbInterface(MongoInterfaceCommon):

    READ_ONLY = True
    RELEVANT_FILE_TYPES = AnalysisPlugin.ARCHIVE_MIME_TYPES + AnalysisPlugin.FS_MIME_TYPES

    def parent_fo_has_fs_metadata_analysis_results(self, file_object: FileObject):
        for parent_uid in self.get_parent_uids_from_virtual_path(file_object):
            if self.existence_quick_check(parent_uid):
                parent_fo = self.get_object(parent_uid)
                if 'file_type' in parent_fo.processed_analysis and \
                        parent_fo.processed_analysis['file_type']['mime'] in self.RELEVANT_FILE_TYPES:
                    return True
        return False

    @staticmethod
    def get_parent_uids_from_virtual_path(file_object: FileObject):
        result = set()
        for path_list in file_object.virtual_file_path.values():
            for virtual_path in path_list:
                with suppress(IndexError):
                    result.add(virtual_path.split("|")[-2])
        return result

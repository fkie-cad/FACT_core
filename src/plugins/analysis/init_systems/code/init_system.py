from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Optional, Union

from pydantic import BaseModel, Field
from semver import Version

from analysis.plugin import AnalysisPluginV0

if TYPE_CHECKING:
    from io import FileIO

FILE_IGNORES = {'README', 'README.md', 'README.txt', 'INSTALL', 'VERSION'}


class InitType(str, Enum):
    init_tab = 'inittab'
    initscript = 'initscript'
    rc = 'rc'
    runit = 'RunIt'
    sys_v_init = 'SysVInit'
    systemd = 'SystemD'
    upstart = 'UpStart'


class SystemDData(BaseModel):
    exec_start: Optional[str] = None
    description: Optional[str] = None


class InitTabData(BaseModel):
    sysinit: Optional[str] = None
    respawn: Optional[str] = None


class UpstartData(BaseModel):
    exec: Optional[str] = None
    pre_start: Optional[str] = None
    description: Optional[str] = None


class SysVInitData(BaseModel):
    description: Optional[str] = None
    short_description: Optional[str] = None


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        init_type: Optional[InitType] = Field(
            None, description='The type of init system that was identified for this file'
        )
        data: Optional[Union[SystemDData, InitTabData, UpstartData, SysVInitData]] = Field(
            None,
            description='Optional meta information and init data contained in this init script',
        )
        is_init: bool = False

        @classmethod
        def __get_validators__(cls):
            yield cls.validate

        @classmethod
        def validate(cls, value):
            init_type = value.get('init_type')
            if init_type == InitType.systemd:
                value['data'] = SystemDData(**value['data'])
            elif init_type == InitType.init_tab:
                value['data'] = InitTabData(**value['data'])
            elif init_type == InitType.upstart:
                value['data'] = UpstartData(**value['data'])
            elif init_type == InitType.sys_v_init:
                value['data'] = SysVInitData(**value['data'])
            return cls(**value)

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='init_systems',
                    mime_whitelist=['text/plain'],
                    description='detect and analyze initialization scripts',
                    version=Version(1, 0, 0),
                    Schema=self.Schema,
                )
            )
        )

    SYSTEMD_EXECSTART_REGEX = re.compile(r'ExecStart=(.*)')
    SYSTEMD_DESCRIPTION_REGEX = re.compile(r'Description=(.*)')

    def _get_systemd_config(self, file_handle: FileIO) -> Schema:
        content = file_handle.read().decode(errors='ignore')
        return self.Schema(
            is_init=True,
            init_type=InitType.systemd,
            data=SystemDData(
                exec_start=_match(content, self.SYSTEMD_EXECSTART_REGEX),
                description=_match(content, self.SYSTEMD_DESCRIPTION_REGEX),
            ),
        )

    INITTAB_SYSINIT_REGEX = re.compile(r'^[^#].*(?<=sysinit:)([^#].*)', re.MULTILINE)
    INITTAB_RESPAWN_REGEX = re.compile(r'^[^#].*(?<=respawn:)([^#].*)', re.MULTILINE)

    def _get_inittab_config(self, file_handle: FileIO) -> Schema:
        content = file_handle.read().decode(errors='ignore')
        return self.Schema(
            is_init=True,
            init_type=InitType.init_tab,
            data=InitTabData(
                sysinit=_match(content, self.INITTAB_SYSINIT_REGEX),
                respawn=_match(content, self.INITTAB_RESPAWN_REGEX),
            ),
        )

    UPSTART_DESCRIPTION_REGEX = re.compile(r'^[^#].*(?<=description)\s*(.*)', re.MULTILINE)
    UPSTART_EXEC_REGEX = re.compile(r'[^#]^exec\s*((?:.*\\\n)*.*)', re.MULTILINE)
    UPSTART_PRESTART_REGEX = re.compile(r'(?<=pre-start script\n)[\S\s]*?\n*(?=\nend script)', re.MULTILINE)

    def _get_upstart_config(self, file_handle: FileIO) -> Schema:
        content = file_handle.read().decode(errors='ignore')
        return self.Schema(
            is_init=True,
            init_type=InitType.upstart,
            data=UpstartData(
                description=_match(content, self.UPSTART_DESCRIPTION_REGEX),
                exec=_match(content, self.UPSTART_EXEC_REGEX),
                pre_start=_match(content, self.UPSTART_PRESTART_REGEX),
            ),
        )

    SYSVINIT_SHORT_DESC_REGEX = re.compile(r'Short-Description:\s*(.*)', re.MULTILINE)
    SYSVINIT_DESC_REGEX = re.compile(r'DESC=\"*([^\"|\n]*)', re.MULTILINE)

    def _get_sysvinit_config(self, file_handle: FileIO) -> Schema:
        content = file_handle.read().decode(errors='ignore')
        return self.Schema(
            is_init=True,
            init_type=InitType.sys_v_init,
            data=SysVInitData(
                description=_match(content, self.SYSVINIT_DESC_REGEX),
                short_description=_match(content, self.SYSVINIT_SHORT_DESC_REGEX),
            ),
        )

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel | dict]) -> Schema:
        del analyses
        file_path = list(virtual_file_path.values())[0][0]
        if Path(file_path).name not in FILE_IGNORES:
            result = self._get_script_type_from_path(file_path, file_handle)
            if result.is_init and not self._has_no_content(file_handle):
                return result
        return self.Schema(is_init=False)

    def _get_script_type_from_path(self, file_path: str, file_handle: FileIO) -> Schema:  # noqa: PLR0911
        if '/inittab' in file_path:
            return self._get_inittab_config(file_handle)
        if 'systemd/system/' in file_path:
            return self._get_systemd_config(file_handle)
        if file_path.endswith(('etc/rc', 'etc/rc.local', 'etc/rc.firsttime', 'etc/rc.securelevel')):
            return self.Schema(is_init=True, init_type=InitType.rc)
        if file_path.endswith('etc/initscript'):
            return self.Schema(is_init=True, init_type=InitType.initscript)
        if 'etc/init/' in file_path or 'etc/event.d/' in file_path:
            return self._get_upstart_config(file_handle)
        if 'etc/service/' in file_path or 'etc/sv/' in file_path:
            return self.Schema(is_init=True, init_type=InitType.runit)
        if 'etc/init.d/' in file_path or 'etc/rc.d/' in file_path:
            return self._get_sysvinit_config(file_handle)
        return self.Schema(is_init=False)

    def summarize(self, result: Schema) -> list[str]:
        if result.is_init and result.init_type:
            return [result.init_type]
        return []

    @staticmethod
    def _has_no_content(file_handle: FileIO) -> bool:
        file_handle.seek(0)
        content = file_handle.read().decode(errors='ignore')
        return all(line.startswith('#') for line in content.splitlines() if line)


def _match(content: str, regex: re.Pattern) -> str | None:
    if match := regex.findall(content):
        return '\n'.join(match)
    return None

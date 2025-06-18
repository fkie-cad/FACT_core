from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

from pydantic import BaseModel
from semver import Version

from analysis.plugin import AnalysisPluginV0, Tag
from analysis.plugin.compat import AnalysisBasePluginAdapterMixin
from helperFunctions.tag import TagColor
from plugins.analysis.kernel_config.internal.checksec_check_kernel import CHECKSEC_PATH, check_kernel_config
from plugins.analysis.kernel_config.internal.decomp import GZDecompressor
from plugins.analysis.kernel_config.internal.kernel_config_hardening_check import (
    HardeningCheckResult,
    check_kernel_hardening,
)
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

if TYPE_CHECKING:
    from io import FileIO

    from plugins.analysis.file_type.code.file_type import AnalysisPlugin as FileTypePlugin
    from plugins.analysis.software_components.code.software_components import AnalysisPlugin as SoftwarePlugin

IKCONFIG_START_MAGIC = b'IKCFG_ST'
IKCONFIG_END_MAGIC = b'IKCFG_ED'
GZIP_MAGIC = bytes.fromhex('1f 8b')


class CheckSec(BaseModel):
    kernel: dict
    selinux: dict


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    class Schema(BaseModel):
        is_kernel_config: bool
        kernel_config: Optional[str] = None
        checksec: Optional[CheckSec] = None
        hardening: Optional[List[HardeningCheckResult]] = None

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='kernel_config',
                    dependencies=['file_type', 'software_components'],
                    description=(
                        'Heuristics to find and analyze Linux Kernel configurations via checksec and '
                        'kconfig-hardened-check'
                    ),
                    mime_blacklist=MIME_BLACKLIST_NON_EXECUTABLE,
                    version=Version(1, 0, 0),
                    Schema=self.Schema,
                )
            )
        )
        if not CHECKSEC_PATH.is_file():
            raise RuntimeError(f'checksec not found at path {CHECKSEC_PATH}. Please re-run the backend installation.')
        self.config_pattern = re.compile(r'^(CONFIG|# CONFIG)[_ -]\w[\w -]*=(\d+|[ymn])$', re.MULTILINE)
        self.kernel_pattern_new = re.compile(r'^# Linux.* Kernel Configuration$', re.MULTILINE)
        self.kernel_pattern_old = re.compile(r'^# Linux kernel version: [\d.]+$', re.MULTILINE)

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]) -> Schema:
        file_content = file_handle.read()

        kernel_config: str | None = None
        if self._is_kconfig(file_content, analyses['file_type']):
            kernel_config = file_content.decode(errors='replace')
        elif self._contains_kconfig(analyses['software_components'], virtual_file_path):
            maybe_config = try_extracting_kconfig(file_content)
            if self._is_probably_kconfig(maybe_config):
                kernel_config = maybe_config.decode(errors='replace')

        return self.Schema(
            is_kernel_config=kernel_config is not None,
            kernel_config=kernel_config,
            checksec=check_kernel_config(kernel_config) if kernel_config else None,
            hardening=check_kernel_hardening(kernel_config) if kernel_config else None,
        )

    @staticmethod
    def _contains_kconfig(software_analysis: SoftwarePlugin.Schema, vfp_dict: dict[str, list[str]]) -> bool:
        return _has_filename('configs.ko', vfp_dict) or object_is_kernel_image(software_analysis)

    def _is_kconfig(self, file_content: bytes, file_type_analysis: FileTypePlugin.Schema) -> bool:
        return file_type_analysis.mime == 'text/plain' and (
            self._has_kconfig_type(file_type_analysis) or self._is_probably_kconfig(file_content)
        )

    @staticmethod
    def _has_kconfig_type(file_type_analysis: FileTypePlugin.Schema) -> bool:
        return 'Linux make config' in file_type_analysis.full

    def summarize(self, result: Schema) -> list[str]:
        return ['Kernel Config'] if result.is_kernel_config else []

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del summary
        if result.is_kernel_config:
            return [Tag(name='IKCONFIG', value='Kernel Configuration', color=TagColor.LIGHT_BLUE)]
        return []

    def _is_probably_kconfig(self, raw_data: bytes) -> bool:
        try:
            content = raw_data.decode()
        except UnicodeDecodeError:
            return False

        config_directives = self.config_pattern.findall(content)
        kernel_config_banner = self.kernel_pattern_new.findall(content) or self.kernel_pattern_old.findall(content)

        return len(kernel_config_banner) > 0 and len(config_directives) > 0


def try_extracting_kconfig(raw_data: bytes) -> bytes:
    start_offset = raw_data.find(IKCONFIG_START_MAGIC)
    end_offset = raw_data.find(IKCONFIG_END_MAGIC, start_offset)
    if start_offset < 0 or end_offset < 0:
        # ikconfig may be encapsulated in compression container => "linuxkernel" unpacking plugin should unpack this
        # container and the kernel_config should be found when this file is analyzed so we just return here
        return b''
    start_offset += len(IKCONFIG_START_MAGIC)

    if raw_data[start_offset : start_offset + len(GZIP_MAGIC)] != GZIP_MAGIC:
        return b''  # the kernel config should always be GZIP compressed

    return GZDecompressor.decompress(raw_data[start_offset:end_offset])


def object_is_kernel_image(software_analysis: SoftwarePlugin.Schema) -> bool:
    return any('linux kernel' in component.name.lower() for component in software_analysis.software_components)


def _has_filename(file_name, vfp_dict: dict[str, list[str]]) -> bool:
    return any(file_name == Path(path).name for path_list in vfp_dict.values() for path in path_list)

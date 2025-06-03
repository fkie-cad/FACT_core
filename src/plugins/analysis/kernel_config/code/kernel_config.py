from __future__ import annotations

import re
from typing import TYPE_CHECKING

from analysis.PluginBase import AnalysisBasePlugin
from plugins.analysis.kernel_config.internal.checksec_check_kernel import CHECKSEC_PATH, check_kernel_config
from plugins.analysis.kernel_config.internal.decomp import GZDecompressor
from plugins.analysis.kernel_config.internal.kernel_config_hardening_check import check_kernel_hardening
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

if TYPE_CHECKING:
    from objects.file import FileObject

IKCONFIG_START_MAGIC = b'IKCFG_ST'
IKCONFIG_END_MAGIC = b'IKCFG_ED'
GZIP_MAGIC = bytes.fromhex('1f 8b')


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'kernel_config'
    DESCRIPTION = 'Heuristics to find and analyze Linux Kernel configurations via checksec and kconfig-hardened-check'
    MIME_BLACKLIST = MIME_BLACKLIST_NON_EXECUTABLE
    DEPENDENCIES = ['file_type', 'software_components']  # noqa: RUF012
    VERSION = '0.4.0'
    FILE = __file__

    def additional_setup(self):
        if not CHECKSEC_PATH.is_file():
            raise RuntimeError(f'checksec not found at path {CHECKSEC_PATH}. Please re-run the backend installation.')
        self.config_pattern = re.compile(r'^(CONFIG|# CONFIG)[_ -]\w[\w -]*=(\d+|[ymn])$', re.MULTILINE)
        self.kernel_pattern_new = re.compile(r'^# Linux.* Kernel Configuration$', re.MULTILINE)
        self.kernel_pattern_old = re.compile(r'^# Linux kernel version: [\d.]+$', re.MULTILINE)

    def process_object(self, file_object: FileObject) -> FileObject:
        file_object.processed_analysis[self.NAME] = {}

        if self.object_mime_is_plaintext(file_object) and (
            self.has_kconfig_type(file_object) or self.probably_kernel_config(file_object.binary)
        ):
            self.add_kernel_config_to_analysis(file_object, file_object.binary)
        elif file_object.file_name == 'configs.ko' or self.object_is_kernel_image(file_object):
            maybe_config = self.try_object_extract_ikconfig(file_object.binary)
            if maybe_config and self.probably_kernel_config(maybe_config):
                self.add_kernel_config_to_analysis(file_object, maybe_config)

        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(
            file_object.processed_analysis[self.NAME]
        )

        if 'kernel_config' in file_object.processed_analysis[self.NAME]:
            file_object.processed_analysis[self.NAME]['checksec'] = check_kernel_config(
                file_object.processed_analysis[self.NAME]['kernel_config']
            )
            file_object.processed_analysis[self.NAME]['hardening'] = check_kernel_hardening(
                file_object.processed_analysis[self.NAME]['kernel_config']
            )

        return file_object

    @staticmethod
    def has_kconfig_type(file_object: FileObject) -> bool:
        file_type_str = file_object.processed_analysis.get('file_type', {}).get('result', {}).get('full', '')
        return 'Linux make config' in file_type_str

    @staticmethod
    def _get_summary(results: dict) -> list[str]:
        if 'is_kernel_config' in results and results['is_kernel_config'] is True:
            return ['Kernel Config']
        return []

    def add_kernel_config_to_analysis(self, file_object: FileObject, config_bytes: bytes):
        file_object.processed_analysis[self.NAME]['is_kernel_config'] = True
        file_object.processed_analysis[self.NAME]['kernel_config'] = config_bytes.decode()
        self.add_analysis_tag(file_object, 'IKCONFIG', 'Kernel Configuration')

    def probably_kernel_config(self, raw_data: bytes) -> bool:
        try:
            content = raw_data.decode()
        except UnicodeDecodeError:
            return False

        config_directives = self.config_pattern.findall(content)
        kernel_config_banner = self.kernel_pattern_new.findall(content) or self.kernel_pattern_old.findall(content)

        return len(kernel_config_banner) > 0 and len(config_directives) > 0

    @staticmethod
    def try_object_extract_ikconfig(raw_data: bytes) -> bytes:
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

    @staticmethod
    def object_mime_is_plaintext(file_object: FileObject) -> bool:
        return file_object.processed_analysis.get('file_type', {}).get('result', {}).get('mime') == 'text/plain'

    @staticmethod
    def object_is_kernel_image(file_object: FileObject) -> bool:
        return (
            'software_components' in file_object.processed_analysis
            and 'summary' in file_object.processed_analysis['software_components']
            and any(
                'linux kernel' in component.lower()
                for component in file_object.processed_analysis['software_components']['summary']
            )
        )

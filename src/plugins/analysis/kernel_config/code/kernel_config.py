import re
import sys
from pathlib import Path
from typing import List

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject

try:
    from ..internal.decomp import decompress
    from ..internal.kernel_config_hardening_check import check_kernel_hardening
    from ..internal.checksec_check_kernel import check_kernel_config, CHECKSEC_PATH
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from decomp import decompress
    from kernel_config_hardening_check import check_kernel_hardening
    from checksec_check_kernel import check_kernel_config, CHECKSEC_PATH


MAGIC_WORD = b'IKCFG_ST\037\213'


class AnalysisPlugin(AnalysisBasePlugin):
    NAME = 'kernel_config'
    DESCRIPTION = 'Heuristics to find and analyze Linux Kernel configurations via checksec and kconfig-hardened-check'
    MIME_BLACKLIST = ['audio', 'filesystem', 'image', 'video']
    DEPENDENCIES = ['file_type', 'software_components']
    VERSION = '0.3'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config

        if not CHECKSEC_PATH.is_file():
            raise RuntimeError(f'checksec not found at path {CHECKSEC_PATH}. Please re-run the backend installation.')

        self.config_pattern = re.compile(r'^(CONFIG|# CONFIG)_\w+=(\d+|[ymn])$', re.MULTILINE)
        self.kernel_pattern = re.compile(r'^# Linux.* Kernel Configuration$', re.MULTILINE)

        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object: FileObject) -> FileObject:
        file_object.processed_analysis[self.NAME] = dict()

        if self.object_mime_is_plaintext(file_object) and self.probably_kernel_config(file_object.binary):
            self.add_kernel_config_to_analysis(file_object, file_object.binary)
        elif file_object.file_name == 'configs.ko' or self.object_is_kernel_image(file_object):
            maybe_config = self.try_object_extract_ikconfig(file_object.binary)
            if self.probably_kernel_config(maybe_config):
                self.add_kernel_config_to_analysis(file_object, maybe_config)

        file_object.processed_analysis[self.NAME]['summary'] = self._get_summary(file_object.processed_analysis[self.NAME])

        if 'kernel_config' in file_object.processed_analysis[self.NAME]:
            file_object.processed_analysis[self.NAME]['checksec'] = check_kernel_config(file_object.processed_analysis[self.NAME]['kernel_config'])
            file_object.processed_analysis[self.NAME]['hardening'] = check_kernel_hardening(file_object.processed_analysis[self.NAME]['kernel_config'])

        return file_object

    @staticmethod
    def _get_summary(results: dict) -> List[str]:
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
        kernel_config_banner = self.kernel_pattern.findall(content)

        return len(kernel_config_banner) > 0 and len(config_directives) > 0

    @staticmethod
    def try_object_extract_ikconfig(raw_data: bytes) -> bytes:
        container = raw_data
        if raw_data.find(MAGIC_WORD) < 0:
            # ikconfig is encapsulated in compression container => absence of magic word
            inner = decompress(container)
            if len(inner) == 0:
                return b''
            container = inner[0]

        start_offset = container.find(MAGIC_WORD)
        if start_offset < 0:
            return b''

        maybe_configs = decompress(container[start_offset:])

        if len(maybe_configs) == 0:
            return b''

        return maybe_configs[0]

    @staticmethod
    def object_mime_is_plaintext(file_object: FileObject) -> bool:
        analysis = file_object.processed_analysis
        return 'file_type' in analysis and \
               'mime' in analysis['file_type'] and \
               analysis['file_type']['mime'] == 'text/plain'

    @staticmethod
    def object_is_kernel_image(file_object: FileObject) -> bool:
        return 'software_components' in file_object.processed_analysis and \
               'summary' in file_object.processed_analysis['software_components'] and \
               any('linux kernel' in component.lower() for component in file_object.processed_analysis['software_components']['summary'])

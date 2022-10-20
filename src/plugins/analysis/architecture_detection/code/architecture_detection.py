from typing import Dict

from analysis.PluginBase import AnalysisBasePlugin
from storage.fsorganizer import FSOrganizer

try:
    from ..internal import dt, elf, kconfig, metadata
except ImportError:
    import sys
    from pathlib import Path

    sys.path.append(str(Path(__file__).parent.parent / 'internal'))

    import dt
    import elf
    import kconfig
    import metadata

    sys.path.pop()


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Generically detected target architecture for firmware images.
    '''

    FILE = __file__
    NAME = 'cpu_architecture'
    DESCRIPTION = 'identify CPU architecture'
    VERSION = '0.4.0'

    DEPENDENCIES = ['file_type', 'kernel_config', 'device_tree']
    MIME_BLACKLIST = [
        'application/msword',
        'application/pdf',
        'application/postscript',
        'application/x-dvi',
        'application/x-httpd-php',
        'application/xhtml+xml',
        'application/xml',
        'image',
        'video',
    ]

    def __init__(self, plugin_administrator, config=None):
        self.config = config
        self._fs_organizer = FSOrganizer(config)
        super().__init__(plugin_administrator, config=config)

    def process_object(self, file_object):
        arch_dict = construct_result(file_object, self._fs_organizer)
        file_object.processed_analysis[self.NAME]['architectures'] = arch_dict
        file_object.processed_analysis[self.NAME]['summary'] = list(arch_dict.keys())

        return file_object


def construct_result(file_object, fs_organizer) -> Dict[str, str]:
    '''
    Returns a dict where keys are the architecture and values are the means of
    detection
    '''
    result = {}
    result.update(dt.construct_result(file_object))
    result.update(kconfig.construct_result(file_object))
    result.update(elf.construct_result(file_object, fs_organizer))
    result.update(metadata.construct_result(file_object))

    return result

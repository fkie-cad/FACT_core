from __future__ import annotations

from analysis.PluginBase import AnalysisBasePlugin
from storage.fsorganizer import FSOrganizer

from ..internal import dt, elf, kconfig, metadata


class AnalysisPlugin(AnalysisBasePlugin):
    """
    Generically detected target architecture for firmware images.
    """

    FILE = __file__
    NAME = 'cpu_architecture'
    DESCRIPTION = 'identify CPU architecture'
    VERSION = '0.4.0'

    DEPENDENCIES = ['file_type', 'kernel_config', 'device_tree']  # noqa: RUF012
    MIME_BLACKLIST = [  # noqa: RUF012
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

    def __init__(self):
        self._fs_organizer = FSOrganizer()
        super().__init__()

    def process_object(self, file_object):
        arch_dict = construct_result(file_object, self._fs_organizer)
        file_object.processed_analysis[self.NAME]['architectures'] = arch_dict
        file_object.processed_analysis[self.NAME]['summary'] = list(arch_dict.keys())

        return file_object


def construct_result(file_object, fs_organizer) -> dict[str, str]:
    """
    Returns a dict where keys are the architecture and values are the means of
    detection
    """
    result = {}
    result.update(dt.construct_result(file_object))
    result.update(kconfig.construct_result(file_object))
    result.update(elf.construct_result(file_object, fs_organizer))
    result.update(metadata.construct_result(file_object))

    return result

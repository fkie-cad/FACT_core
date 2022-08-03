import logging
from pathlib import Path
from typing import List

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.typing import JsonDict
from objects.file import FileObject

try:
    from ..internal.metadata_detector import MetaDataDetector
except ImportError:
    import sys
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from metadata_detector import MetaDataDetector


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Generically detected target architecture for firmware images.
    '''
    NAME = 'cpu_architecture'
    DEPENDENCIES = ['file_type']
    DESCRIPTION = 'identify CPU architecture'
    VERSION = '0.3.3'
    FILE = __file__
    MIME_BLACKLIST = [
        'application/msword',
        'application/pdf',
        'application/postscript',
        'application/x-dvi',
        'application/x-httpd-php',
        'application/xhtml+xml',
        'application/xml',
        'image',
        'text',
        'video',
    ]

    detectors = [MetaDataDetector()]

    def do_analysis(self, file_object: FileObject) -> JsonDict:
        for detector in self.detectors:
            arch_dict = detector.get_device_architecture(file_object)
            if arch_dict:
                return arch_dict
        logging.debug(f'Arch Detection Failed: {file_object.uid}')
        return {}

    @staticmethod
    def create_summary(analysis_result: JsonDict) -> List[str]:
        return list(analysis_result)

import logging
from pathlib import Path

from analysis.PluginBase import AnalysisBasePlugin

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

    def process_object(self, file_object):
        '''
        This function must be implemented by the plugin.
        Analysis result must be a list stored in file_object.processed_analysis[self.NAME]
        '''
        arch_dict = self._get_device_architectures(file_object)
        file_object.processed_analysis[self.NAME] = arch_dict
        file_object.processed_analysis[self.NAME]['summary'] = list(arch_dict.keys())
        return file_object

    def _get_device_architectures(self, file_object):
        for detector in self.detectors:
            arch_dict = detector.get_device_architecture(file_object)
            if arch_dict:
                return arch_dict
        logging.debug(f'Arch Detection Failed: {file_object.uid}')
        return {}

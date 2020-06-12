import logging

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Generically detected target architecture for firmware images.
    '''
    NAME = 'cpu_architecture'
    DEPENDENCIES = ['file_type']
    DESCRIPTION = 'identify CPU architecture'
    VERSION = '0.3.2'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        propagate flag: If True add analysis result of child to parent object
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config
        self.MIME_BLACKLIST = [
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
        self.DETECTORS = [MetaDataDetector()]
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

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
        for detector in self.DETECTORS:
            arch_dict = detector.get_device_architecture(file_object)
            if arch_dict:
                return arch_dict
        logging.debug('Arch Detection Failed: {}'.format(file_object.uid))
        return {}


class MetaDataDetector:
    '''
    Architecture detection based on metadata
    '''

    architectures = {
        'ARM': ['ARM'],
        'PPC': ['PowerPC', 'PPC'],
        'MIPS': ['MIPS'],
        'x86': ['x86', '80386', '80486'],
        'SPARC': ['SPARC'],
        'RISC': ['RISC', 'RS6000', '80960', '80860'],
        'S/390': ['IBM S/390'],
        'SuperH': ['Renesas SH'],
        'Alpha': ['Alpha'],
        'M68K': ['m68k', '68020']
    }
    bitness = {
        '16-bit': ['16-bit'],
        '32-bit': ['32-bit', 'PE32'],
        '64-bit': ['64-bit', 'aarch64', 'x86-64', '80860']
    }
    endianness = {
        'little endian': ['LSB', '80386', '80486', 'x86'],
        'big endian': ['MSB']
    }

    def get_device_architecture(self, file_object):
        type_of_file = file_object.processed_analysis['file_type']['full']
        arch_dict = file_object.processed_analysis.get('cpu_architecture', dict())
        end_result = self._search_for_arch_keys(type_of_file, self.architectures, delimiter='')
        if not end_result:
            return arch_dict
        end_result += '{bitness}{endianness} (M)'.format(
            bitness=self._search_for_arch_keys(type_of_file, self.bitness),
            endianness=self._search_for_arch_keys(type_of_file, self.endianness)
        )
        arch_dict.update({end_result: 'Detection based on meta data'})
        return arch_dict

    @staticmethod
    def _search_for_arch_keys(file_type_output, arch_dict, delimiter=', '):
        for key in arch_dict:
            for bit in arch_dict[key]:
                if bit in file_type_output:
                    return delimiter + key
        return ''

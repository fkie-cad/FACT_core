import logging

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Generically detected target architecture for firmware images.
    '''
    NAME = 'cpu_architecture'
    DEPENDENCIES = ['file_type']
    DESCRIPTION = 'identify CPU architecture'
    VERSION = '0.3.3'
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

    def __init__(self, plugin_administrator, config=None, recursive=True):
        '''
        recursive flag: If True recursively analyze included files
        propagate flag: If True add analysis result of child to parent object
        default flags should be edited above. Otherwise the scheduler cannot overwrite them.
        '''
        self.config = config
        self.detectors = [MetaDataDetector()]
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
        for detector in self.detectors:
            arch_dict = detector.get_device_architecture(file_object)
            if arch_dict:
                return arch_dict
        logging.debug(f'Arch Detection Failed: {file_object.uid}')
        return {}


class MetaDataDetector:
    '''
    Architecture detection based on metadata
    '''

    architectures = {
        'ARC': ['ARC Cores'],
        'ARM': ['ARM'],
        'AVR': ['Atmel AVR'],
        'PPC': ['PowerPC', 'PPC'],
        'MIPS': ['MIPS'],
        'x86': ['x86', '80386', '80486'],
        'SPARC': ['SPARC'],
        'RISC-V': ['RISC-V'],
        'RISC': ['RISC', 'RS6000', '80960', '80860'],
        'S/390': ['IBM S/390'],
        'SuperH': ['Renesas SH'],
        'ESP': ['Tensilica Xtensa'],
        'Alpha': ['Alpha'],
        'M68K': ['m68k', '68020'],
        'Tilera': ['TILE-Gx', 'TILE64', 'TILEPro']
    }
    bitness = {
        '8-bit': ['8-bit'],
        '16-bit': ['16-bit'],
        '32-bit': ['32-bit', 'PE32', 'MIPS32'],
        '64-bit': ['64-bit', 'aarch64', 'x86-64', 'MIPS64', '80860']
    }
    endianness = {
        'little endian': ['LSB', '80386', '80486', 'x86'],
        'big endian': ['MSB']
    }

    def get_device_architecture(self, file_object):
        type_of_file = file_object.processed_analysis['file_type']['full']
        arch_dict = file_object.processed_analysis.get('cpu_architecture', dict())
        architecture = self._search_for_arch_keys(type_of_file, self.architectures, delimiter='')
        if not architecture:
            return arch_dict
        bitness = self._search_for_arch_keys(type_of_file, self.bitness)
        endianness = self._search_for_arch_keys(type_of_file, self.endianness)
        full_isa_result = f'{architecture}{bitness}{endianness} (M)'
        arch_dict.update({full_isa_result: 'Detection based on meta data'})
        return arch_dict

    @staticmethod
    def _search_for_arch_keys(file_type_output, arch_dict, delimiter=', '):
        for key in arch_dict:
            for bit in arch_dict[key]:
                if bit in file_type_output:
                    return delimiter + key
        return ''

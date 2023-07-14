class MetaDataDetector:
    """
    Architecture detection based on metadata
    """

    architectures = {  # noqa: RUF012
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
        'Tilera': ['TILE-Gx', 'TILE64', 'TILEPro'],
    }
    bitness = {  # noqa: RUF012
        '8-bit': ['8-bit'],
        '16-bit': ['16-bit'],
        '32-bit': ['32-bit', 'PE32', 'MIPS32'],
        '64-bit': ['64-bit', 'aarch64', 'x86-64', 'MIPS64', '80860'],
    }
    endianness = {'little endian': ['LSB', '80386', '80486', 'x86'], 'big endian': ['MSB']}  # noqa: RUF012

    def get_device_architecture(self, file_object):
        type_of_file = file_object.processed_analysis['file_type']['result']['full']
        arch_dict = file_object.processed_analysis.get('cpu_architecture', {})
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

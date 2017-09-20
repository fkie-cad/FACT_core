from time import gmtime
from struct import unpack


class UbootInvalidCPUArchitecture(Exception):
    pass


class UbootInvalidOS(Exception):
    pass


class UbootInvalidCompression(Exception):
    pass


class UbootInvalidImageType(Exception):
    pass


class uBootHeader():
    HEADER_NAME_LENGTH = 32
    HEADER_LENGTH = 64
    ARCH = {0: 'Invalid',
            1: 'Alpha',
            2: 'ARM',
            3: 'Intel X86',
            4: 'IA64',
            5: 'MIPS',
            6: 'MIPS_64bit',
            7: 'PowerPC',
            8: 'IBM S390',
            9: 'SuperH',
            10: 'Sparc',
            11: 'Sparc 64bit',
            12: 'M68k',
            13: 'NIOS-32',
            14: 'MicroBlaze',
            15: 'NIOS II',
            16: 'Blackfin',
            17: 'AVR32',
            18: 'STMicroelectronis ST200',
            19: 'Sandbox Architecture Test Only',
            20: 'ANDES Technology NDS32',
            21: 'OpenRISC 1000',
            22: 'ARM64',
            23: 'Synopsys DesignWare ARC',
            24: 'AMD x86_64'}

    OS = {0: 'Invalid',
          1: 'OpenBSD',
          2: 'NetBSD',
          3: 'FreeBSD',
          4: 'four_four_BSD',
          5: 'Linux',
          6: 'SVR4',
          7: 'Esix',
          8: 'Solaris0',
          9: 'Irix',
          10: 'SCO',
          11: 'Dell',
          12: 'NCR',
          13: 'LynxOS',
          14: 'VxWorks',
          15: 'pSoS',
          16: 'QNX',
          17: 'Firmware_uBoot',
          18: 'RTEMS',
          19: 'ARTOS',
          20: 'Unity_OS',
          21: 'INTEGRITY',
          22: 'OSE',
          23: 'Plan 9',
          }

    COMPRESSION = {0: 'none', 1: 'gz', 2: 'gz2', 3: 'lzma', 4: 'lzo'}

    TYPE = {0: 'Invalid',
            1: 'Standalone_program',
            2: 'OS_Kernel_image',
            3: 'RAMDisk_image',
            4: 'Multi_File_image',
            5: 'Firmware_image',
            6: 'Script_file',
            7: 'Filesystem_image',
            8: 'Binary_Flat_Device_Blob',
            9: 'Kirkwood_Boot_image',
            10: 'Freescale_IMXBoot_image',
            11: 'Davinci_UBL_image',
            12: 'TI_OMAP_Config_Header_image',
            13: 'TI_Davinci_AIS_image',
            14: 'OS_Kernel_image_no_load',
            15: 'Freescale_PBL_Boot_image',
            16: 'Freescale_MSXSBoot_image',
            17: 'TI_Keystone_GPHeader_image',
            18: 'ATMEL_ROM_bootable_image',
            19: 'Altera_SOCFPGA_Preloader',
            20: 'x86_setupbin_image'}

    def __str__(self):
        return self.image_name

    def __init__(self):
        self.magic = None
        self.header_crc = None
        self.timestamp = None
        self.image_data_size = None
        self.data_load_address = None
        self.entry_point = None
        self.image_data_crc = None
        self.operating_system = None
        self.cpu_architecture = None
        self.image_type = None
        self.compression_type = None
        self.image_name = None

    def create_from_binary(self, BINARY):
        header = unpack('>4sIIIIIIBBBB32s', BINARY[0:64])

        self.magic = header[0]
        self.header_crc = header[1]
        self.timestamp = gmtime(header[2])
        self.image_data_size = header[3]
        self.data_load_address = header[4]
        self.entry_point = header[5]
        self.image_data_crc = header[6]

        if header[7] in self.OS:
            self.operating_system = header[7]
        else:
            raise UbootInvalidOS()

        if header[8] in self.ARCH:
            self.cpu_architecture = header[8]
        else:
            raise UbootInvalidCPUArchitecture()

        if header[9] in self.TYPE:
            self.image_type = header[9]
        else:
            raise UbootInvalidImageType

        if header[10] in self.COMPRESSION:
            self.compression_type = header[10]
        else:
            raise UbootInvalidCompression

        self.image_name = header[11].replace(b'\x00', b'').decode(encoding='UTF-8')

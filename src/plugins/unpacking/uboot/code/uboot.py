import mmap
import os
import sys

from unpacker.helper.carving import Carver

THIS_FILE = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(THIS_FILE, '..', 'internal'))
from uboot_container import uBootHeader

name = 'Uboot'
mime_patterns = ['firmware/u-boot']
version = '0.1'


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''

    unpacker = Uboot(file_path)

    uboot_path = '{}/uboot.{}'.format(tmp_dir, uBootHeader.COMPRESSION[unpacker.ubootheader.compression_type])
    with open(uboot_path, 'wb') as uboot:
        uboot.write(unpacker.extract_uboot_image())

    uboot_header_path = '{}/uboot_header.bin'.format(tmp_dir)
    with open(uboot_header_path, 'wb') as uboot:
        uboot.write(unpacker.extract_uboot_header())

    remaining = unpacker.get_remaining_blocks()
    for offset in remaining:
        unknown_path = '{}/{}_unknown.bin'.format(tmp_dir, offset)
        with open(unknown_path, 'wb') as hdr:
            hdr.write(remaining[offset])

    return {}


class Uboot:
    def __init__(self, filename):
        self.firmware_filepath = filename

        statinfo = os.stat(self.firmware_filepath)
        self.firmware_size = statinfo.st_size

        self.carver = Carver(self.firmware_filepath)
        self.ubootheader = self._set_uboot_header()

    def get_remaining_blocks(self):
        non_carved_areas = self.carver.carved.non_carved_areas

        remaining = {}
        for area in non_carved_areas:
            remaining[area[0]] = self.carver.extract_data(area[0], area[1])
        return remaining

    def extract_uboot_image(self):
        return self.carver.extract_data(uBootHeader.HEADER_LENGTH, uBootHeader.HEADER_LENGTH + self.ubootheader.image_data_size)

    def _set_uboot_header(self):
        with open(self.firmware_filepath, 'r+b') as f:
            mm = mmap.mmap(f.fileno(), 0)

            ubootheader = uBootHeader()
            ubootheader.create_from_binary(mm.read(uBootHeader.HEADER_LENGTH))
        return ubootheader

    def extract_uboot_header(self):
        return self.carver.extract_data(0, uBootHeader.HEADER_LENGTH)

# ----> Do not edit below this line <----


def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

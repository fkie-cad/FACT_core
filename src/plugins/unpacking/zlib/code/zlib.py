'''
This plugin unpacks Zlib streams.
'''
import os
import zlib

from common_helper_files import get_binary_from_file, write_binary_to_file

name = 'Zlib'
mime_patterns = ['compression/zlib']
version = '0.1'


def unpack_function(file_path, tmp_dir):
    """
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    Optional: Return a dict with meta information
    """
    raw_data = get_binary_from_file(file_path)
    decompressed_data = zlib.decompress(raw_data)
    output_file_path = os.path.join(tmp_dir, "zlib_decompressed")
    write_binary_to_file(decompressed_data, output_file_path)
    return {}


# ----> Do not edit below this line <----

def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

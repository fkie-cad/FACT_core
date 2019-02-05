'''
This plugin unpacks dahua firmware images
'''
from common_helper_files import get_binary_from_file, write_binary_to_file
from pathlib import Path

name = 'dahua'
mime_patterns = ['firmware/dahua']
version = '0.1'


def unpack_function(file_path, tmp_dir):
    output_file_path = Path(tmp_dir, 'dahua_firmware.zip')
    original = get_binary_from_file(file_path)
    fixed = b'PK' + original[2:]
    write_binary_to_file(fixed, str(output_file_path))
    return {'output': 'zip header fixed'}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

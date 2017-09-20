'''
This plugin unpacks SquashFS filesystem images
'''
from common_helper_process import execute_shell_command
import logging

name = 'SquashFS'
mime_patterns = ['filesystem/squashfs']
version = '0.6'
squash_unpacker = 'sasquatch'


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''
    output = execute_shell_command('fakeroot {} -d {}/faf_extracted {}'.format(squash_unpacker, tmp_dir, file_path))
    return {'output': output}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

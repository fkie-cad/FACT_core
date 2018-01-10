'''
This plugin unpacks all files via carving
'''
import logging

from common_helper_process import execute_shell_command

name = 'generic_carver'
mime_patterns = ['generic/carver']
version = '0.7'


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''

    logging.debug('File Type unknown: execute binwalk on {}'.format(file_path))
    output = execute_shell_command('binwalk --extract --carve --signature --directory  {} {}'.format(tmp_dir, file_path))
    return {'output': output}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

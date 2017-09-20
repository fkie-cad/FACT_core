'''
This plugin unpacks StuffIt files (.sit, .sitx)
'''
from common_helper_process import execute_shell_command

name = 'StuffItFile'
mime_patterns = ['application/x-stuffit', 'application/x-sit', 'application/x-stuffitx', 'application/x-sitx']
version = '0.3'
stuffit_unpacker = 'unar'


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''
    output = execute_shell_command('fakeroot {} -o {} {}'.format(stuffit_unpacker, tmp_dir, file_path))
    return {'output': output}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

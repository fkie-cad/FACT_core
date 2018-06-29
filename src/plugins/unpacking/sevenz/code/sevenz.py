'''
This plugin uses 7z to extract several formats
'''
import os

from common_helper_passwords import get_merged_password_set
from common_helper_process import execute_shell_command

from helperFunctions.fileSystem import get_src_dir

name = '7z'
mime_patterns = ['application/x-lzma', 'application/x-7z-compressed', 'application/zip', 'application/x-zip-compressed']
unpacker_program = '7z'
version = '0.7'

PW_LIST = get_merged_password_set(os.path.join(get_src_dir(), 'unpacker/passwords'))


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''
    meta = {}
    for password in PW_LIST:
        execution_string = 'fakeroot {} x -y -p{} -o{} {}'.format(unpacker_program, password, tmp_dir, file_path)
        output = execute_shell_command(execution_string)

        meta['output'] = output
        if 'Wrong password' not in output:
            if 'AES' in output:
                meta['password'] = password
            break
    return meta


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

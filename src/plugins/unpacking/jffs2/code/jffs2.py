'''
This plugin unpacks JFFS2 filesystem images
'''
import logging
import os

from common_helper_process import execute_shell_command

name = 'JFFS2'
mime_patterns = ['filesystem/jffs2', 'filesystem/jffs2-big']
version = '0.5'


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    local_tmp_dir should be used to store the extracted files.
    '''

    extract_dir = os.path.join(tmp_dir, 'jffs-root')
    output = execute_shell_command('fakeroot jefferson -v -d {} {}'.format(extract_dir, file_path)) + '\n'
    meta_data = {'output': output}
    logging.debug(output)
    return meta_data


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

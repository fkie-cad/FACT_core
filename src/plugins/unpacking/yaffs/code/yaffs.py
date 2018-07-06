from os import path

from common_helper_process import execute_shell_command

from helperFunctions.fileSystem import get_faf_bin_dir


name = 'YAFFS'
mime_patterns = ['filesystem/yaffs']
version = '0.4'

path_to_unyaffs = '/usr/bin/unyaffs'
path_to_unyaffs2 = path.join(get_faf_bin_dir(), 'unyaffs2')


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''
    unpacker = '{} -e'.format(path_to_unyaffs2) if _is_big_endian(file_path) else '{} -v'.format(path_to_unyaffs)
    output = execute_shell_command('fakeroot {} {} {}'.format(unpacker, file_path, tmp_dir))
    return {'output': output}


def _is_big_endian(file_path):
    with open(file_path, 'br') as fp:
        content = fp.read(10)
        big_endian = content[7:] == b'\x01\xFF\xFF'
    return big_endian


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

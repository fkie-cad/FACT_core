'''
This plugin unpacks SquashFS filesystem images
'''
import os

from common_helper_files import get_files_in_dir
from common_helper_process import execute_shell_command

THIS_FILES_DIR = os.path.dirname(os.path.abspath(__file__))
BIN_DIR = os.path.join(THIS_FILES_DIR, '../bin')


name = 'SquashFS'
mime_patterns = ['filesystem/squashfs']
version = '0.7'
squash_unpacker = ['sasquatch', BIN_DIR + '/unsquashfs4-avm-be', BIN_DIR + '/unsquashfs4-avm-le', BIN_DIR + '/unsquashfs4-avm-le']


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''
    unpack_result = dict()
    for unpacker in squash_unpacker:
        output = execute_shell_command('fakeroot {} -d {}/fact_extracted {}'.format(unpacker, tmp_dir, file_path))
        if _unpack_success(tmp_dir):
            unpack_result['unpacking_tool'] = _get_unpacker_name(unpacker)
            unpack_result['output'] = output
            break
        else:
            unpack_result['{} - error'.format(_get_unpacker_name(unpacker))] = output
    return unpack_result


def _get_unpacker_name(unpacker_path):
    return unpacker_path.split('/')[-1]


def _unpack_success(tmp_dir):
    return len(get_files_in_dir(tmp_dir)) > 0


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

'''
This plugin unpacks SquashFS filesystem images
'''
from tempfile import TemporaryDirectory

from common_helper_process import execute_shell_command

from helperFunctions.fileSystem import get_file_type_from_path

name = 'genericFS'
mime_patterns = ['generic/fs', 'filesystem/cramfs', 'filesystem/romfs', 'filesystem/btrfs', 'filesystem/ext2',
                 'filesystem/ext3', 'filesystem/ext4', 'filesystem/dosmbr', 'filesystem/hfs',
                 'filesystem/jfs', 'filesystem/minix', 'filesystem/reiserfs', 'filesystem/udf', 'filesystem/xfs']
version = '0.4'
type_dict = {
    'filesystem/cramfs': 'cramfs', 'filesystem/romfs': 'romfs', 'filesystem/btrfs': 'btrfs',
    'filesystem/minix': 'minix', 'filesystem/reiserfs': 'reiserfs', 'filesystem/jfs': 'jfs',
    'filesystem/udf': 'udf', 'filesystem/xfs': 'xfs'
}


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''

    mime_type = get_file_type_from_path(file_path)['mime']
    type_parameter = '-t {}'.format(type_dict[mime_type]) if mime_type in type_dict else ''

    mount_dir = TemporaryDirectory()
    output = execute_shell_command('sudo mount {} -v -o ro,loop {} {}'.format(type_parameter, file_path, mount_dir.name))
    output += execute_shell_command('sudo cp -av {}/* {}/'.format(mount_dir.name, tmp_dir))
    output += execute_shell_command('sudo umount -v {}'.format(mount_dir.name))
    mount_dir.cleanup()

    return {'output': output}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

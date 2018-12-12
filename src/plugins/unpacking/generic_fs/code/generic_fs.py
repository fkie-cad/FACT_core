'''
This plugin unpacks SquashFS filesystem images
'''
from tempfile import TemporaryDirectory
import re

from common_helper_process import execute_shell_command, execute_shell_command_get_return_code

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
    if mime_type == 'filesystem/dosmbr':
        output = _mount_from_boot_record(file_path, tmp_dir)
    else:
        output = _mount_single_filesystem(file_path, mime_type, tmp_dir)

    return {'output': output}


def _mount_single_filesystem(file_path, mime_type, tmp_dir):
    type_parameter = '-t {}'.format(type_dict[mime_type]) if mime_type in type_dict else ''
    mount_dir = TemporaryDirectory()
    output = execute_shell_command(
        'sudo mount {} -v -o ro,loop {} {}'.format(type_parameter, file_path, mount_dir.name))
    output += execute_shell_command('sudo cp -av {}/* {}/'.format(mount_dir.name, tmp_dir))
    output += execute_shell_command('sudo umount -v {}'.format(mount_dir.name))
    mount_dir.cleanup()
    return output


def _mount_from_boot_record(file_path, tmp_dir):
    output, return_code = execute_shell_command_get_return_code('sudo kpartx -a -v {}'.format(file_path))
    if not return_code == 0:
        return 'Failed to mount master boot record image:\n{}'.format(output)

    loop_devices = _extract_loop_devices(output)

    mount_dir = TemporaryDirectory()
    for index, loop_device in enumerate(loop_devices):
        output += _mount_loop_device(loop_device, mount_dir.name, tmp_dir, index)
    mount_dir.cleanup()

    if loop_devices:
        # Bug in kpartx doesn't allow -d to work on long file names (as in /storage/path/<prefix>/<sha_hash>_<length>)
        # thus "host" loop device is used instead of filename
        k_output, return_code = execute_shell_command_get_return_code('sudo kpartx -d -v {}'.format(_get_host_loop(loop_devices)))
        return output + k_output

    return output


def _mount_loop_device(loop_device, mount_point, target_directory, index):
    output = execute_shell_command('sudo mount -v /dev/mapper/{} {}'.format(loop_device, mount_point))
    output += execute_shell_command('sudo cp -av {}/ {}/partition_{}/'.format(mount_point, target_directory, index))
    return output + execute_shell_command('sudo umount -v {}'.format(mount_point))


def _extract_loop_devices(kpartx_output):
    return re.findall(r'.*(loop\d{1,2}p\d{1,2})\s.*', kpartx_output)


def _get_host_loop(devices):
    return '/dev/{}'.format(re.findall(r'(loop\d{1,2})', devices[0])[0])


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

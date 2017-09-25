'''
This plugin unpacks avm file system container
'''
from common_helper_process import execute_shell_command

name = 'avm_sqfs_fake'
mime_patterns = ['filesystem/avm-sqfs-fake']
version = '0.1'


def unpack_function(file_path, tmp_dir):
    output = execute_shell_command('dd if={} of={}/image.ext2 bs=256 skip=1 conv=sync'.format(file_path, tmp_dir))
    return {'output': output}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

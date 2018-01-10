import os

from common_helper_process.fail_safe_subprocess import execute_shell_command

from helperFunctions.fileSystem import get_faf_bin_dir

name = 'ROSFile'
mime_patterns = ['firmware/ros']
version = '0.7'

TOOL_PATH = os.path.join(get_faf_bin_dir(), 'ros_unpack')


def unpack_function(file_path, tmp_dir):
    '''
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    '''
    output = execute_shell_command('(cd {} && fakeroot {} --extract {})'.format(tmp_dir, TOOL_PATH, file_path))
    return {'output': output}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

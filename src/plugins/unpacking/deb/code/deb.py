'''
This plugin unpacks debian packages
'''
from common_helper_process import execute_shell_command

name = 'Deb'
mime_patterns = ['application/vnd.debian.binary-package']
version = '0.1'


def unpack_function(file_path, tmp_dir):
    return {'output': execute_shell_command('fakeroot dpkg-deb -v -x {} {}'.format(file_path, tmp_dir))}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

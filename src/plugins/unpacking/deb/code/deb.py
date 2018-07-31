'''
This plugin unpacks debian packages
'''
import logging

from common_helper_process import execute_shell_command

from helperFunctions.process import program_is_callable

name = 'Deb'
mime_patterns = ['application/vnd.debian.binary-package']
version = '0.1'


def unpack_function(file_path, tmp_dir):
    if not program_is_callable("fakeroot"):
        logging.error("fakeroot not working")
    elif not program_is_callable("dpkg-deb"):
        logging.error("dpkg-deb not working!")
    else:
        return {'output': execute_shell_command('fakeroot dpkg-deb -v -x {} {}'.format(file_path, tmp_dir))}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

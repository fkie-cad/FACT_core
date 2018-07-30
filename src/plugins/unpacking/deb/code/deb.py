'''
This plugin unpacks debian packages
'''
import logging
from subprocess import Popen, PIPE, STDOUT

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
        with Popen('fakeroot dpkg-deb -v -x {} {}'.format(file_path, tmp_dir), shell=True, stdout=PIPE, stderr=STDOUT) as dpkg_process:
            output = dpkg_process.communicate()[0].decode(encoding='utf_8', errors='replace')
        return {'output': output}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

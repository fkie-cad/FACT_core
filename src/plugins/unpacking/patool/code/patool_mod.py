'''
This plugin unpacks several formats utilizing patool
'''
import logging
from subprocess import Popen, PIPE, STDOUT

from helperFunctions.process import program_is_callable

name = 'PaTool'
mime_patterns = ['application/x-lrzip', 'application/x-cpio', 'application/x-archive', 'application/x-adf',
                 'application/x-redhat-package-manager', 'application/x-rpm', 'application/x-lzop', 'application/x-lzh',
                 'application/x-lha', 'application/x-cab', 'application/vnd.ms-cab-compressed', 'application/zpaq',
                 'application/x-chm', 'application/x-arj', 'application/x-gzip',
                 'application/gzip', 'application/x-bzip2', 'application/x-dms',
                 'application/x-debian-package', 'application/x-rzip', 'application/x-tar', 'application/x-shar',
                 'application/x-lzip', 'application/x-alzip', 'application/x-rar', 'application/rar',
                 'application/java-archive',
                 'application/x-iso9660-image', 'application/x-compress', 'application/x-arc', 'audio/flac',
                 'application/x-ace', 'application/x-zoo', 'application/x-xz']
version = '0.5'


def unpack_function(file_path, tmp_dir):
    """
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    """
    if not program_is_callable("fakeroot"):
        logging.error("fakeroot not working")
    elif not program_is_callable("patool"):
        logging.error("patool not working!")
    else:
        with Popen('fakeroot patool extract --outdir {} {}'.format(tmp_dir, file_path), shell=True, stdout=PIPE, stderr=STDOUT) as pl:
            output = pl.communicate()[0].decode(encoding='utf_8', errors='replace')
        return {'output': output}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

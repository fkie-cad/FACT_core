'''
Extractcs Upgrade Files from HP Printer Job Language (PJL) files
'''
import sys
from pathlib import Path

from common_helper_files import get_binary_from_file

INTERNAL_DIR = Path(__file__).parent.parent / 'internal'
sys.path.append(str(INTERNAL_DIR))

from pjl_helper import (
    extract_all_upgrades, extract_fingerprint, get_pjl_commands
)


name = 'PJL'
mime_patterns = ['firmware/hp-pjl']
version = '0.3'


def unpack_function(file_path, tmp_dir):
    """
    file_path specifies the input file.
    tmp_dir should be used to store the extracted files.
    Optional: Return a dict with meta information
    """
    file_binary = get_binary_from_file(file_path)
    pjl_commands = get_pjl_commands(file_binary)
    extract_all_upgrades(file_binary, pjl_commands, tmp_dir)
    extract_fingerprint(file_binary, tmp_dir)
    return {'pjl_commands': pjl_commands}


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

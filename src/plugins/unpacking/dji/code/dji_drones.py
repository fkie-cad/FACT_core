# -*- coding: utf-8 -*-

import re
from os import path, rename

from common_helper_files import get_files_in_dir, delete_file
from common_helper_process import execute_shell_command

from helperFunctions.fileSystem import get_faf_bin_dir

name = 'DJI_drones'
mime_patterns = ['firmware/dji-drone']
version = '0.3.1'

TOOL_PATH = path.join(get_faf_bin_dir(), 'dji_xv4_fwcon.py')


def unpack_function(file_path, tmp_dir):
    if not path.exists(TOOL_PATH):
        return {'output': 'Error: phantom_firmware_tools not installed! Re-Run the installation script!'}

    output = execute_shell_command('(cd {} && fakeroot python3 {} -x -vv -p {})'.format(tmp_dir, TOOL_PATH, file_path)) + '\n'

    _rename_files(tmp_dir)
    _remove_ini_files(tmp_dir)
    meta_data = {'output': output}
    return meta_data


def _rename_files(tmp_dir):
    files = _get_list_of_files(tmp_dir)

    for ini_file, bin_file in files:
        module_id = _extract_module_id(bin_file)
        if module_id:
            identifier = _get_identifier_from_ini(ini_file)
            rename(bin_file, '{}/{}_{}.module'.format(tmp_dir, module_id, identifier))


def _get_list_of_files(tmp_dir):
    all_files = get_files_in_dir(tmp_dir)
    bin_files = [any_file for any_file in all_files if any_file.endswith('bin')]
    files = [('{}ini'.format(bin_file[:len(bin_file) - 3]), bin_file) for bin_file in bin_files]
    return files


def _extract_module_id(bin_file):
    id_match = re.match(r'.*(m[0-9]{4})\.bin', bin_file)
    if not id_match:
        return None
    module_id = id_match.group(1)
    return module_id


def _get_identifier_from_ini(ini_file):
    identifier = 'default'
    with open(ini_file, 'r') as fd:
        lines = fd.readlines()
        for line in lines:
            match = re.match(r'\#.Stores.firmware.for.([0-9a-zA-Z ]*)', line)
            if match:
                identifier = match.group(1)
                identifier = identifier.replace(' ', '_')
                identifier = identifier.strip('_')
    return identifier


def _remove_ini_files(tmp_dir):
    for file_name in get_files_in_dir(tmp_dir):
        if file_name.endswith('.ini'):
            delete_file(file_name)


# ----> Do not edit below this line <----
def setup(unpack_tool):
    for item in mime_patterns:
        unpack_tool.register_plugin(item, (unpack_function, name, version))

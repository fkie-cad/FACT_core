#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2020  Fraunhofer FKIE

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import os
from subprocess import CalledProcessError
from tempfile import NamedTemporaryFile

from common_helper_files import get_files_in_dir, get_dirs_in_dir
from common_helper_process import execute_shell_command

from helperFunctions.fileSystem import get_src_dir

SIGNATURE_DIR = os.path.join(get_src_dir(), 'analysis/signatures')


def _create_joint_signature_file(directory, tmp_file):
    all_signatures = list()
    for signature_file in sorted(get_files_in_dir(directory)):
        with open(signature_file, 'rb') as fd:
            all_signatures.append(fd.read())

    with open(tmp_file.name, 'wb') as fd:
        fd.write(b'\x0a'.join(all_signatures))


def _get_plugin_name(plugin_path):
    return plugin_path.split('/')[-2]


def _create_compiled_signature_file(directory, tmp_file):
    target_path = os.path.join(SIGNATURE_DIR, '{}.yc'.format(_get_plugin_name(directory)))
    try:
        command = 'yarac -d test_flag=false {} {}'.format(tmp_file.name, target_path)
        execute_shell_command(command, check=True)
    except CalledProcessError:
        print('[ERRROR] Creation of {} failed !!'.format(os.path.split(target_path)[0]))


def _create_signature_dir():
    print('Create signature directory {}'.format(SIGNATURE_DIR))
    os.makedirs(SIGNATURE_DIR, exist_ok=True)


def main():
    _create_signature_dir()
    for plugin_dir in get_dirs_in_dir(os.path.join(get_src_dir(), 'plugins/analysis')):
        signature_dir = os.path.join(plugin_dir, 'signatures')
        if os.path.isdir(signature_dir):
            print('Compile signatures in {}'.format(signature_dir))
            with NamedTemporaryFile(mode='w') as tmp_file:
                _create_joint_signature_file(signature_dir, tmp_file)
                _create_compiled_signature_file(signature_dir, tmp_file)

    return 0


if __name__ == '__main__':
    exit(main())

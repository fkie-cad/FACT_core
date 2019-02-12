#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2019  Fraunhofer FKIE

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
from pathlib import Path

from common_helper_process import execute_shell_command_get_return_code
from helperFunctions.install import OperateInDirectory

MIME_DIR = Path(Path(__file__).parent, 'mime')


def main():
    with OperateInDirectory(str(MIME_DIR)):
        cat_output, cat_code = execute_shell_command_get_return_code('cat custom_* > custommime')
        file_output, file_code = execute_shell_command_get_return_code('file -C -m custommime')
        mv_output, mv_code = execute_shell_command_get_return_code('mv -f custommime.mgc ../bin/')
        if any(code != 0 for code in (cat_code, file_code, mv_code)):
            exit('Failed to properly compile magic file\n{}'.format('\n'.join((cat_output, file_output, mv_output))))
        Path('custommime').unlink()


if __name__ == '__main__':
    exit(main())

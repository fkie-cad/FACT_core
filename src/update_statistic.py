#! /usr/bin/env python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2022  Fraunhofer FKIE

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

import sys

from helperFunctions.program_setup import program_setup
from statistic.update import StatsUpdater

PROGRAM_NAME = 'FACT Statistic Updater'
PROGRAM_DESCRIPTION = 'Initialize or update FACT statistic'


def main(command_line_options=None):
    if command_line_options is None:
        command_line_options = sys.argv
    program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION, command_line_options=command_line_options)

    updater = StatsUpdater()
    updater.update_all_stats()

    return 0


if __name__ == '__main__':
    sys.exit(main())

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

import logging
import sys

from helperFunctions.program_setup import program_setup
from statistic.update import StatisticUpdater
from storage.mongodb_docker import start_db_container

PROGRAM_NAME = 'FACT Statistic Updater'
PROGRAM_DESCRIPTION = 'Initialize or update FACT statistic'


def main(command_line_options=None):
    command_line_options = sys.argv if not command_line_options else command_line_options
    _, config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION, command_line_options=command_line_options)

    logging.info('Trying to start Mongo Server...')
    with start_db_container(config):
        updater = StatisticUpdater(config=config)
        updater.update_all_stats()
        updater.shutdown()

    return 0


if __name__ == '__main__':
    sys.exit(main())

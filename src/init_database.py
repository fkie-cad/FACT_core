#!/usr/bin/python3
'''
    Firmware Analysis and Comparison Tool (FACT)
    Copyright (C) 2015-2018  Fraunhofer FKIE

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

from storage.MongoMgr import MongoMgr
from helperFunctions.program_setup import program_setup


PROGRAM_NAME = 'FACT Database Initializer'
PROGRAM_DESCRIPTION = 'Initialize authentication and users for FACT\'s Database'


def main(command_line_options=None):
    command_line_options = sys.argv if command_line_options is None else command_line_options
    _, config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION, command_line_options=command_line_options)

    logging.info('Trying to start Mongo Server and initializing users...')
    mongo_manger = MongoMgr(config=config, auth=False)
    mongo_manger.init_users()
    mongo_manger.shutdown()

    return 0


if __name__ == '__main__':
    sys.exit(main())

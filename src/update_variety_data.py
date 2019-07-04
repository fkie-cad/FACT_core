#! /usr/bin/env python3
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
import os
import sys
from time import time

from common_helper_filter import time_format
from common_helper_process import execute_shell_command_get_return_code

from helperFunctions.fileSystem import get_src_dir
from helperFunctions.program_setup import program_setup
from storage.MongoMgr import MongoMgr

PROGRAM_NAME = 'FACT Variety Data Updater'
PROGRAM_DESCRIPTION = 'Initialize or update database structure information used by the "advanced search" feature.'


def _create_variety_data(config):
    full_variety_path = os.path.join(get_src_dir(), config['data_storage']['variety_path'])
    output, return_code = execute_shell_command_get_return_code(
        'mongo --port {mongo_port} {main_database} -u "{username}" -p "{password}" --authenticationDatabase "admin" '
        '--eval "var collection = \'file_objects\', persistResults=true" {script_path}'.format(
            mongo_port=config['data_storage']['mongo_port'],
            username=config['data_storage']['db_admin_user'],
            password=config['data_storage']['db_admin_pw'],
            main_database=config['data_storage']['main_database'],
            script_path=full_variety_path),
        timeout=None
    )
    logging.debug(output)
    return return_code


def main(command_line_options=None):
    command_line_options = sys.argv if command_line_options is None else command_line_options
    args, config = program_setup(PROGRAM_NAME, PROGRAM_DESCRIPTION, command_line_options=command_line_options)

    logging.info('Try to start Mongo Server...')
    mongo_server = MongoMgr(config=config)

    logging.info('updating data... this may take several hours depending on the size of your database')

    start_time = time()
    return_code = _create_variety_data(config)
    process_time = time() - start_time

    logging.info('generation time: {}'.format(time_format(process_time)))

    if args.testing:
        logging.info('Stopping Mongo Server...')
        mongo_server.shutdown()

    return return_code


if __name__ == '__main__':
    sys.exit(main())

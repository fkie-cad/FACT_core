#! /usr/bin/env python3
'''
    FACT Installer
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

import argparse
import logging
import sys
from pathlib import Path

try:
    import distro

    from common_helper_process import execute_shell_command_get_return_code

    from helperFunctions.install import OperateInDirectory
    from install.common import main as common
    from install.frontend import main as frontend
    from install.backend import main as backend
    from install.db import main as db
except ImportError:
    sys.exit('Could not import install dependencies. Please (re-)run install/pre_install.sh')

PROGRAM_NAME = 'FACT Installer'
PROGRAM_VERSION = '1.1'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Comparison Tool (FACT) installation script'

INSTALL_CANDIDATES = ['frontend', 'db', 'backend']

BIONIC_CODE_NAMES = ['bionic', 'tara', 'tessa', 'tina', 'disco']
XENIAL_CODE_NAMES = ['xenial', 'yakkety', 'sarah', 'serena', 'sonya', 'sylvia']
DEBIAN_CODE_NAMES = ['buster', 'stretch', 'kali-rolling']
FOCAL_CODE_NAMES = ['focal']


def _setup_argparser():
    parser = argparse.ArgumentParser(description='{} - {}'.format(PROGRAM_NAME, PROGRAM_DESCRIPTION))
    parser.add_argument('-V', '--version', action='version', version='{} {}'.format(PROGRAM_NAME, PROGRAM_VERSION))
    install_options = parser.add_argument_group('Install Options', 'Choose which components should be installed')
    for item in INSTALL_CANDIDATES:
        install_options.add_argument('-{}'.format(item[0].upper()), '--{}'.format(item), action='store_true', default=False, help='install {}'.format(item))
    install_options.add_argument('-N', '--nginx', action='store_true', default=False, help='install and configure nginx')
    install_options.add_argument('-R', '--no_radare', action='store_true', default=False, help='do not install radare view container')
    install_options.add_argument('-U', '--statistic_cronjob', action='store_true', default=False, help='install cronjob to update statistics hourly and variety data once a week.')
    logging_options = parser.add_argument_group('Logging and Output Options')
    logging_options.add_argument('-l', '--log_file', help='path to log file', default='./install.log')
    logging_options.add_argument('-L', '--log_level', help='define the log level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='WARNING')
    logging_options.add_argument('-d', '--debug', action='store_true', help='print debug messages', default=False)
    return parser.parse_args()


def _get_console_output_level(debug_flag):
    if debug_flag:
        return logging.DEBUG
    return logging.INFO


def _setup_logging(log_level, log_file, debug_flag=False):
    try:
        log_level = getattr(logging, log_level, None)
        log_format = logging.Formatter(fmt='[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        logger = logging.getLogger('')
        logger.setLevel(logging.DEBUG)
        create_dir_for_file(log_file, dir_description='logging directory')
        file_log = logging.FileHandler(log_file)
        file_log.setLevel(log_level)
        file_log.setFormatter(log_format)
        console_log = logging.StreamHandler()
        console_log.setLevel(_get_console_output_level(debug_flag))
        console_log.setFormatter(log_format)
        logger.addHandler(file_log)
        logger.addHandler(console_log)
    except Exception as exception:
        sys.exit('Error: Could not setup logging: {} {}'.format(type(exception).__name__, exception))


def create_dir_for_file(file_path: str, dir_description='directory'):
    '''
    Creates the directory of the file_path.
    '''
    try:
        Path(file_path).absolute().parent.mkdir(parents=True, exist_ok=True)
    except Exception as exception:
        sys.exit('Error: Could not create {}: {} {}'.format(dir_description, type(exception).__name__, exception))


def get_directory_of_current_file() -> Path:
    return Path(__file__).parent.absolute()


def welcome():
    logging.info('{} {}'.format(PROGRAM_NAME, PROGRAM_VERSION))


def check_python_version():
    if sys.version_info.major != 3 or sys.version_info.minor < 5:
        sys.exit('Error: Incompatible Python version! You need at least version 3.5! Your Version: {}'.format(sys.version))


def check_distribution():
    codename = distro.codename().lower()
    if codename in XENIAL_CODE_NAMES:
        logging.debug('Ubuntu 16.04 detected')
        return 'xenial'
    if codename in BIONIC_CODE_NAMES:
        logging.debug('Ubuntu 18.04 detected')
        return 'bionic'
    if codename in FOCAL_CODE_NAMES:
        logging.debug('Ubuntu 20.04 detected')
        return 'focal'
    if codename in DEBIAN_CODE_NAMES:
        logging.debug('Debian/Kali detected')
        return 'debian'
    sys.exit('Your Distribution ({} {}) is not supported. FACT Installer requires Ubuntu 16.04, Ubuntu 18.04 or compatible!'.format(distro.id(), distro.version()))


def install_statistic_cronjob():
    logging.info('install cronjob for statistic and variety data updates')
    current_dir = get_directory_of_current_file()
    statistic_update_script_path = current_dir / 'update_statistic.py'
    variety_update_script_path = current_dir / 'update_variety_data.py'
    crontab_file_path = current_dir.parent / 'update_statistic.cron'
    cron_content = '0    *    *    *    *    {} > /dev/null 2>&1\n'.format(statistic_update_script_path)
    cron_content += '30    0    *    *    0    {} > /dev/null 2>&1\n'.format(variety_update_script_path)
    crontab_file_path.write_text(cron_content)
    output, return_code = execute_shell_command_get_return_code('crontab {}'.format(crontab_file_path))
    if return_code != 0:
        logging.error(output)
    else:
        logging.info('done')


def install():
    check_python_version()
    args = _setup_argparser()
    _setup_logging(args.log_level, args.log_file, debug_flag=args.debug)
    welcome()
    distribution = check_distribution()
    none_chosen = not (args.frontend or args.db or args.backend)

    installation_directory = get_directory_of_current_file() / 'install'

    with OperateInDirectory(str(installation_directory)):
        common(distribution)

        if args.frontend or none_chosen:
            frontend(not args.no_radare, args.nginx)
        if args.db or none_chosen:
            db(distribution)
        if args.backend or none_chosen:
            backend()

    if args.statistic_cronjob:
        install_statistic_cronjob()

    logging.info('installation complete')
    logging.warning('If FACT does not start, reload the environment variables with: source /etc/profile')

    sys.exit()


if __name__ == '__main__':
    install()

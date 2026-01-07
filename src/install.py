#! /usr/bin/env python3
"""
    FACT Installer
    Copyright (C) 2015-2026  Fraunhofer FKIE

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
"""

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path
from subprocess import PIPE, STDOUT

try:
    import config
    from helperFunctions.install import OperateInDirectory, check_distribution
    from install.backend import _install_docker_images as backend_install_docker_images
    from install.backend import install_plugin_docker_images as backend_install_plugin_docker_images
    from install.backend import main as backend
    from install.common import main as common
    from install.db import main as db
    from install.frontend import _install_docker_images as frontend_install_docker_images
    from install.frontend import main as frontend
except ImportError:
    logging.critical('Could not import install dependencies. Please (re-)run install/pre_install.sh', exc_info=True)
    sys.exit(1)

PROGRAM_NAME = 'FACT Installer'
PROGRAM_VERSION = '1.2'
PROGRAM_DESCRIPTION = 'Firmware Analysis and Comparison Tool (FACT) installation script'

FACT_INSTALLER_SKIP_DOCKER = os.getenv('FACT_INSTALLER_SKIP_DOCKER')


def _setup_argparser():
    parser = argparse.ArgumentParser(description=f'{PROGRAM_NAME} - {PROGRAM_DESCRIPTION}')
    parser.add_argument('-V', '--version', action='version', version=f'{PROGRAM_NAME} {PROGRAM_VERSION}')
    install_options = parser.add_argument_group('Install Options', 'Choose which components should be installed')
    install_options.add_argument('-B', '--backend', action='store_true', default=False, help='install backend')
    install_options.add_argument('-F', '--frontend', action='store_true', default=False, help='install frontend')
    install_options.add_argument('-D', '--db', action='store_true', default=False, help='install db')
    install_options.add_argument('-C', '--common', action='store_true', default=False, help='install common')
    install_options.add_argument('--no-common', action='store_true', default=False, help='Skip common installation')
    install_options.add_argument(
        '--backend-docker-images',
        action='store_true',
        default=False,
        help='pull/build docker images required to run the backend',
    )
    install_options.add_argument(
        '--frontend-docker-images',
        action='store_true',
        default=False,
        help='pull/build docker images required to run the frontend',
    )
    install_options.add_argument(
        '-N', '--nginx', action='store_true', default=False, help='install and configure nginx'
    )
    install_options.add_argument(
        '-R', '--no_radare', action='store_true', default=False, help='do not install radare view container'
    )
    install_options.add_argument(
        '-H', '--no-hasura', action='store_true', default=False, help='do not set up hasura for GraphQL'
    )
    install_options.add_argument(
        '-U',
        '--statistic_cronjob',
        action='store_true',
        default=False,
        help='install cronjob to update statistics hourly',
    )
    logging_options = parser.add_argument_group('Logging and Output Options')
    logging_options.add_argument('-l', '--log_file', help='path to log file', default='./install.log')
    logging_options.add_argument(
        '-L',
        '--log_level',
        help='define the log level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
    )
    return parser.parse_args()


def _setup_logging(args):
    try:
        log_format = logging.Formatter(
            fmt='[%(asctime)s][%(module)s][%(levelname)s]: %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
        )
        logger = logging.getLogger('')
        logger.setLevel(logging.DEBUG)

        create_dir_for_file(args.log_file, dir_description='logging directory')

        file_log = logging.FileHandler(args.log_file)
        file_log.setLevel(args.log_level)
        file_log.setFormatter(log_format)

        console_log = logging.StreamHandler()
        console_log.setLevel(args.log_level)
        console_log.setFormatter(log_format)

        logger.addHandler(file_log)
        logger.addHandler(console_log)
    except (KeyError, TypeError, ValueError) as exception:
        logging.critical(f'Could not setup logging: {exception}', exc_info=True)
        sys.exit(1)


def create_dir_for_file(file_path: str, dir_description='directory'):
    """
    Creates the directory of the file_path.
    """
    try:
        Path(file_path).absolute().parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        logging.critical(f'Could not create {dir_description}', exc_info=True)
        sys.exit(1)


def get_directory_of_current_file() -> Path:
    return Path(__file__).parent.absolute()


def welcome():
    logging.info(f'{PROGRAM_NAME} {PROGRAM_VERSION}')


def check_python_version():
    if sys.version_info.major != 3 or sys.version_info.minor < 8:  # noqa: PLR2004
        logging.critical(f'Incompatible Python version! You need at least version 3.8! Your Version: {sys.version}')
        sys.exit(1)


def install_statistic_cronjob():
    logging.info('install cronjob for statistic and variety data updates')
    current_dir = get_directory_of_current_file()
    statistic_update_script_path = current_dir / 'update_statistic.py'
    crontab_file_path = current_dir.parent / 'update_statistic.cron'
    cron_content = f'0    *    *    *    *    {statistic_update_script_path} > /dev/null 2>&1\n'
    crontab_file_path.write_text(cron_content)
    crontab_process = subprocess.run(
        f'crontab {crontab_file_path}', shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False
    )
    if crontab_process.returncode != 0:
        logging.error(crontab_process.stdout)
    else:
        logging.info('done')


def install():
    config.load()
    check_python_version()
    args = _setup_argparser()
    _setup_logging(args)
    welcome()
    none_chosen = not (args.frontend or args.db or args.backend or args.common)
    # TODO maybe replace this with an cli argument
    skip_docker = FACT_INSTALLER_SKIP_DOCKER is not None
    # Note that the skip_docker environment variable overrides the cli argument
    only_docker = not skip_docker and none_chosen and (args.backend_docker_images or args.frontend_docker_images)

    # When just pulling the docker images we don't depend on anything distribution specific
    distribution = check_distribution(allow_unsupported=only_docker)

    installation_directory = get_directory_of_current_file() / 'install'

    with OperateInDirectory(str(installation_directory)):
        if not only_docker:
            install_fact_components(args, distribution, none_chosen, skip_docker)
        else:
            install_docker_images(args)

    if args.statistic_cronjob:
        install_statistic_cronjob()

    logging.info('installation complete')

    sys.exit(0)


def install_fact_components(args, distribution, none_chosen, skip_docker):
    if (args.common or args.frontend or args.backend or none_chosen) and not args.no_common:
        common(distribution)
    if args.db or none_chosen:
        db()
    if args.frontend or none_chosen:
        frontend(skip_docker, not args.no_radare, args.nginx, distribution, args.no_hasura)
    if args.backend or none_chosen:
        backend(skip_docker, distribution)


def install_docker_images(args):
    if args.backend_docker_images:
        backend_install_docker_images()
        backend_install_plugin_docker_images()
    if args.frontend_docker_images:
        frontend_install_docker_images(not args.no_radare)


if __name__ == '__main__':
    install()

#! /usr/bin/env python3
'''
    FACT Installer
    Copyright (C) 2015-2017  Fraunhofer FKIE

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
import os
import argparse
import logging
import subprocess

PROGRAM_NAME = "FACT Installer"
PROGRAM_VERSION = "0.7"
PROGRAM_DESCRIPTION = "Firmware Analysis and Comparison Tool (FACT) installation script"

INSTALL_CANDIDATES = ['frontend', 'db', 'backend']


def _setup_argparser():
    parser = argparse.ArgumentParser(description="{} - {}".format(PROGRAM_NAME, PROGRAM_DESCRIPTION))
    parser.add_argument('-V', '--version', action='version', version="{} {}".format(PROGRAM_NAME, PROGRAM_VERSION))
    install_options = parser.add_argument_group('Install Options', "Choose which components should be installed")
    for item in INSTALL_CANDIDATES:
        install_options.add_argument("-{}".format(item[0].upper()), "--{}".format(item), action="store_true", default=False, help="install {}".format(item))
    install_options.add_argument("-N", "--nginx", action="store_true", default=False, help="install and configure nginx")
    install_options.add_argument("-U", "--statistic_cronjob", action="store_true", default=False, help="install cronjob to update statistics hourly")
    logging_options = parser.add_argument_group('Logging and Output Options')
    logging_options.add_argument("-l", "--log_file", help="path to log file", default="./install.log")
    logging_options.add_argument("-L", "--log_level", help="define the log level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="WARNING")
    logging_options.add_argument("-d", "--debug", action="store_true", help="print debug messages", default=False)
    return parser.parse_args()


def _get_console_output_level(debug_flag):
    if debug_flag:
        return logging.DEBUG
    else:
        return logging.INFO


def _setup_logging(args, debug_flag=False):
    try:
        log_level = getattr(logging, args.log_level, None)
        log_format = logging.Formatter(fmt="[%(asctime)s][%(module)s][%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
        logger = logging.getLogger('')
        logger.setLevel(logging.DEBUG)
        create_dir_for_file(args.log_file, dir_description="logging directory")
        file_log = logging.FileHandler(args.log_file)
        file_log.setLevel(log_level)
        file_log.setFormatter(log_format)
        console_log = logging.StreamHandler()
        console_log.setLevel(_get_console_output_level(debug_flag))
        console_log.setFormatter(log_format)
        logger.addHandler(file_log)
        logger.addHandler(console_log)
    except Exception as e:
        sys.exit("Error: Could not setup logging: {} {}".format(sys.exc_info()[0].__name__, e))


def create_dir_for_file(file_path, dir_description="directory"):
    '''
    Creates the directory of the file_path.
    '''
    directory = os.path.dirname(os.path.abspath(file_path))
    try:
        os.makedirs(directory, exist_ok=True)
    except Exception as e:
        sys.exit("Error: Could not create {}: {} {}".format(dir_description, sys.exc_info()[0].__name__, e))


def get_directory_of_current_file():
    return os.path.dirname(os.path.abspath(__file__))


def welcome():
    logging.info("{} {}".format(PROGRAM_NAME, PROGRAM_VERSION))


def check_install_components(args):
    if not (args.frontend or args.db or args.backend):
        logging.debug("no install candidates selected -> installing all")
        install_components = INSTALL_CANDIDATES
    else:
        install_components = []
        if args.frontend:
            install_components.append('frontend')
        if args.db:
            install_components.append('db')
        if args.backend:
            install_components.append('backend')
    logging.info("Installing: {}".format(", ".join(install_components)))
    return install_components


def check_python_version():
    if sys.version_info.major != 3 or sys.version_info.minor < 5:
        sys.exit("Error: Incompatible Python version! You need at least version 3.5! Your Version: {}".format(sys.version))


def check_distribution():
    try:
        import distro
    except ImportError:
        errors = subprocess.run("sudo -EH pip3 install distro", shell=True).stderr
        if errors:
            sys.exit('Could not determine the system´s Linux distribution')
        else:
            import distro
    codename = distro.codename().lower()
    supported_ubuntu_xenial_code_names = ["xenial xerus", "yakkety yak", "sarah", "serena", "sonya"]
    if codename in supported_ubuntu_xenial_code_names:
        logging.debug("Ubuntu 16.04 detected")
        return "xenial"
    else:
        sys.exit("Your Distribution ({} {}) is not supported. FACT Installer requires Ubuntu 16.04 or compatible!".format(distro.id(), distro.version()))


def execute_bootstrap_script(script_name, opts=""):
    logging.info("install {}".format(script_name))
    script_location = os.path.join(get_directory_of_current_file(), "src/bootstrap/bootstrap_{}.sh".format(script_name))
    execution_command = "{} {}".format(script_location, opts)
    errors = subprocess.run(execution_command, shell=True).stderr
    if errors:
        logging.error(errors)
    else:
        logging.info("done")


def install_common_dependencys(args, distribution):
    opts = distribution
    execute_bootstrap_script("common", opts)


def install_frontend(args, distribution):
    opts = distribution
    if args.nginx:
        opts += " nginx"
    execute_bootstrap_script("frontend", opts)


def install_db(args, distribution):
    opts = distribution
    execute_bootstrap_script("db", opts)


def install_backend(args, distribution):
    opts = distribution
    execute_bootstrap_script("backend", opts)


def install_statistic_cronjob():
    logging.info("install cronjob for statistic updates")
    update_script_path = os.path.join(get_directory_of_current_file(), "src/update_statistic.py")
    crontab_file_path = os.path.join(get_directory_of_current_file(), "update_statistic.cron")
    cron_line = "0    *    *    *    *    {} > /dev/null\n".format(update_script_path)
    with open(crontab_file_path, 'w') as f:
        f.write(cron_line)
    errors = subprocess.run("crontab {}".format(crontab_file_path), shell=True).stderr
    if errors:
        logging.error(errors)
    else:
        logging.info("done")


if __name__ == '__main__':
    check_python_version()
    args = _setup_argparser()
    _setup_logging(args, debug_flag=args.debug)
    welcome()
    install_components = check_install_components(args)
    distribution = check_distribution()
    install_common_dependencys(args, distribution)
    if "frontend" in install_components:
        install_frontend(args, distribution)
    if "db" in install_components:
        install_db(args, distribution)
    if "backend" in install_components:
        install_backend(args, distribution)
    if args.statistic_cronjob:
        install_statistic_cronjob()

    logging.info("installation complete")
    logging.warning("If FACT does not start, reload the environment variables with: source /etc/profile")

    sys.exit()

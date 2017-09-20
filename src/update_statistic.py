#! /usr/bin/env python3
'''
This scritp initializes or updates the FAF statistic
'''

import argparse
import configparser
import logging
import sys

from helperFunctions.config import get_config_dir
from storage.MongoMgr import MongoMgr
from statistic.update import StatisticUpdater

PROGRAM_NAME = "FAF Statistic Updater"
PROGRAM_VERSION = "0.1"
PROGRAM_DESCRIPTION = "Initialize or update FAF statistic"


def _setup_argparser():
    parser = argparse.ArgumentParser(description="{} - {}".format(PROGRAM_NAME, PROGRAM_DESCRIPTION))
    parser.add_argument('-V', '--version', action='version', version="{} {}".format(PROGRAM_NAME, PROGRAM_VERSION))
    parser.add_argument("-C", "--config_file", help="set path to config File", default="{}/main.cfg".format(get_config_dir()))
    parser.add_argument("-s", "--shutdown_db", action="store_true", default=False, help="shutdown mongo server after update")
    parser.add_argument("-d", "--debug", action="store_true", default=False, help="print debug messages")
    return parser.parse_args()


def _load_config(args):
    config = configparser.ConfigParser()
    config.read(args.config_file)
    return config


def _setup_logging(args):
    log_format = logging.Formatter(fmt="[%(asctime)s][%(module)s][%(levelname)s]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    logger = logging.getLogger('')
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    console_logger = logging.StreamHandler()
    console_logger.setFormatter(log_format)
    logger.addHandler(console_logger)


if __name__ == '__main__':
    args = _setup_argparser()
    config = _load_config(args)
    _setup_logging(args)

    logging.info("Try to start Mongo Server...")
    mongo_server = MongoMgr(config=config)

    updater = StatisticUpdater(config=config)
    updater.update_all_stats()
    updater.shutdown()

    if args.shutdown_db:
        logging.info("Stopping Mongo Server...")
        mongo_server.shutdown()

    sys.exit()

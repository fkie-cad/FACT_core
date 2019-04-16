from pathlib import Path
from helperFunctions.fileSystem import get_src_dir
import configparser
import logging


def get_path_to_conf():
    return str(Path(get_src_dir()) / 'config' / 'main.cfg')


def load_plugin_conf(input_list):
    config = configparser.ConfigParser()
    config.read(get_path_to_conf())

    threads_info = {}

    for plugin in input_list:
        number_threads = 1

        if plugin in config:
            if config.has_option(plugin, 'threads'):
                number_threads = config[plugin]['threads']
            threads_info.update({plugin: number_threads})
        else:
            threads_info.update({plugin: number_threads})
            logging.warning("plugin(%s) not in main.cfg" % plugin)

    return threads_info

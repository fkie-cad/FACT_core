import configparser
import logging
from configparser import ConfigParser, NoOptionError, NoSectionError
from pathlib import Path

from helperFunctions.fileSystem import get_src_dir
from helperFunctions.process import complete_shutdown


def load_config(config_file_name):
    '''
    loads config of CONFIG_DIR/config_file_name
    Returns config object
    '''
    config = configparser.ConfigParser()
    config_path = '{}/{}'.format(get_config_dir(), config_file_name)
    if not Path(config_path).exists():
        complete_shutdown('config file not found: {}'.format(config_path))
    config.read(config_path)
    return config


def get_config_dir():
    '''
    Returns the absolute path of the config directory
    '''
    return '{}/config'.format(get_src_dir())


def read_list_from_config(config_file: ConfigParser, section: str, key: str, default=None):
    '''
    Parses a comma separated list in section `section` with key `key`.

    :param config_file: The FACT configuration
    :param section: The section to read from
    :param key: The key holding the list

    :return: A list holding the values defined in the config
    '''
    if default is None:
        default = []

    if not config_file:
        return default

    try:
        config_entry = config_file.get(section, key)
    except (NoOptionError, NoSectionError):
        return default

    if not config_entry:
        return default
    return [item.strip() for item in config_entry.split(',') if item]


def get_temp_dir_path(config: ConfigParser = None) -> str:
    '''
    Returns temp_dir_path from the section "data_storage" if it is a valid directory.
    If it does not exist it will be created.
    If the directory does not exist and can not be created or if config is None
    then fallback to "/tmp"

    :param config: The FACT configuration
    '''

    temp_dir_path = config.get('data_storage', 'temp_dir_path', fallback='/tmp') if config else '/tmp'
    if not Path(temp_dir_path).is_dir():
        try:
            Path(temp_dir_path).mkdir()
        except OSError:
            logging.error('TempDir path does not exist and could not be created. Defaulting to /tmp', exc_info=True)
            return '/tmp'
    return temp_dir_path

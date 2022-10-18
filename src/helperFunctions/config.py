import configparser
import logging
from configparser import ConfigParser
from pathlib import Path

from helperFunctions.fileSystem import get_src_dir
from helperFunctions.process import complete_shutdown


def load_config(config_file_name):
    '''
    This function should not be used in new code. Use `config.configparser_cfg` instead.

    loads config of CONFIG_DIR/config_file_name.
    Returns config object.
    Note that this does return a new instance and not the instance provided by `config.configparser_cfg`.
    The returned config may have wrong entries in the logging section.
    '''
    config = configparser.ConfigParser()
    config_path = f'{get_config_dir()}/{config_file_name}'
    if not Path(config_path).exists():
        complete_shutdown(f'config file not found: {config_path}')
    config.read(config_path)
    return config


def get_config_dir():
    '''
    Returns the absolute path of the config directory
    '''
    return f'{get_src_dir()}/config'


def get_temp_dir_path(config: ConfigParser = None) -> str:
    '''
    Returns temp-dir-path from the section "data-storage" if it is a valid directory.
    If it does not exist it will be created.
    If the directory does not exist and can not be created or if config is None
    then fallback to "/tmp"

    :param config: The FACT configuration
    '''

    temp_dir_path = config.get('data-storage', 'temp-dir-path', fallback='/tmp') if config else '/tmp'
    if not Path(temp_dir_path).is_dir():
        try:
            Path(temp_dir_path).mkdir()
        except OSError:
            logging.error('TempDir path does not exist and could not be created. Defaulting to /tmp', exc_info=True)
            return '/tmp'
    return temp_dir_path

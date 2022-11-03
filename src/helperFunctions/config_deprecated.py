import logging
from configparser import ConfigParser
from pathlib import Path

from helperFunctions.fileSystem import get_src_dir


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

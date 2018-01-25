import configparser
import os

from helperFunctions.fileSystem import get_src_dir
from helperFunctions.process import complete_shutdown


def load_config(config_file_name):
    '''
    loads config of CONFIG_DIR/config_file_name
    Returns config object
    '''
    config = configparser.ConfigParser()
    config_path = '{}/{}'.format(get_config_dir(), config_file_name)
    if os.path.exists(config_path):
        config.read(config_path)
        return config
    else:
        complete_shutdown('config file not found: {}'.format(config_path))


def get_config_dir():
    '''
    Returns the absolute path of the config directory
    '''
    return '{}/config'.format(get_src_dir())


def get_config_for_testing(temp_dir=None):
    config = configparser.ConfigParser()
    config.add_section('data_storage')
    config.set('data_storage', 'mongo_server', 'localhost')
    config.set('data_storage', 'main_database', 'tmp_unit_tests')
    config.set('data_storage', 'intercom_database_prefix', 'tmp_unit_tests')
    config.set('data_storage', 'statistic_database', 'tmp_unit_tests')
    config.set('data_storage', 'view_storage', 'tmp_tests_view')
    config.set('data_storage', 'mongo_port', '27018')
    config.set('data_storage', 'report_threshold', '2048')
    config.add_section('unpack')
    config.set('unpack', 'whitelist', '')
    config.set('unpack', 'max_depth', '10')
    config.add_section('ExpertSettings')
    config.set('ExpertSettings', 'block_delay', '1')
    config.set('ExpertSettings', 'ssdeep_ignore', '1')
    faf_config = load_config('main.cfg')
    config.set('data_storage', 'db_admin_user', faf_config['data_storage']['db_admin_user'])
    config.set('data_storage', 'db_admin_pw', faf_config['data_storage']['db_admin_pw'])
    config.set('data_storage', 'db_readonly_user', faf_config['data_storage']['db_readonly_user'])
    config.set('data_storage', 'db_readonly_pw', faf_config['data_storage']['db_readonly_pw'])
    config.add_section('Logging')
    if temp_dir is not None:
        config.set('data_storage', 'firmware_file_storage_directory', temp_dir.name)
        config.set('Logging', 'mongoDbLogFile', os.path.join(temp_dir.name, 'mongo.log'))
    return config

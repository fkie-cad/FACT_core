import shutil
import tempfile
from configparser import ConfigParser
from pathlib import Path
from typing import Dict, Tuple

import pytest

import config
from config import Config
from test.common_helper import create_docker_mount_base_dir


def _get_test_config_tuple(defaults: Dict = None) -> Tuple[Config, ConfigParser]:
    """Returns a tuple containing a `config.Config` instance and a `ConfigParser` instance.
    Both instances are equivalent and the latter is legacy only.
    The "docker-mount-base-dir" and "firmware-file-storage-directory" in the section "data-storage"
    are created and must be cleaned up manually.

    :arg defaults: Sections to overwrite
    """
    config.load_config()

    docker_mount_base_dir = create_docker_mount_base_dir()
    firmware_file_storage_directory = Path(tempfile.mkdtemp())

    # This dict must exactly match the one that a ConfigParser instance would
    # read from the config file
    sections = {
        'data-storage': {
            'postgres-server': 'localhost',
            'postgres-port': '5432',
            'postgres-database': 'fact_test',
            'postgres-test-database': 'fact_test',

            'postgres-ro-user': config.cfg.data_storage.postgres_ro_user,
            'postgres-ro-pw': config.cfg.data_storage.postgres_ro_pw,
            'postgres-rw-user': config.cfg.data_storage.postgres_rw_user,
            'postgres-rw-pw': config.cfg.data_storage.postgres_rw_pw,
            'postgres-del-user': config.cfg.data_storage.postgres_del_user,
            'postgres-del-pw': config.cfg.data_storage.postgres_del_pw,
            'postgres-admin-user': config.cfg.data_storage.postgres_del_user,
            'postgres-admin-pw': config.cfg.data_storage.postgres_del_pw,

            'redis-fact-db': config.cfg.data_storage.redis_test_db,  # Note: This is unused in testing
            'redis-test-db': config.cfg.data_storage.redis_test_db,  # Note: This is unused in production
            'redis-host': config.cfg.data_storage.redis_host,
            'redis-port': config.cfg.data_storage.redis_port,

            'firmware-file-storage-directory': str(firmware_file_storage_directory),

            'user-database': 'sqlite:////media/data/fact_auth_data/fact_users.db',
            'password-salt': '1234',

            'structural-threshold': '40',  # TODO
            'temp-dir-path': '/tmp',
            'docker-mount-base-dir': str(docker_mount_base_dir),
            'variety-path': 'bin/variety.js',
         },
        'database': {
            'ajax-stats-reload-time': '10000',  # TODO
            'number-of-latest-firmwares-to-display': '10',
            'results-per-page': '10'
        },
        'default-plugins': {
            'default': '',
            'minimal': '',
        },
        'expert-settings': {
            'authentication': 'false',
            'block-delay': '0.1',
            'communication-timeout': '60',
            'intercom-poll-delay': '0.5',
            'nginx': 'false',
            'radare2-host': 'localhost',
            'ssdeep-ignore': '1',
            'throw-exceptions': 'false',
            'unpack-threshold': '0.8',
            'unpack_throttle_limit': '50'
        },
        'logging': {
            'logfile': '/tmp/fact_main.log',
            'loglevel': 'WARNING',
        },
        'unpack': {
            'max-depth': '10',
            'memory-limit': '2048',
            'threads': '4',
            'whitelist': ''
        },
        'statistics': {
            'max_elements_per_chart': '10'
        },
    }
    # Update recursively
    for section_name in defaults if defaults else {}:
        sections.setdefault(section_name, {}).update(defaults[section_name])

    configparser_cfg = ConfigParser()
    configparser_cfg.read_dict(sections)

    config._parse_dict(sections)
    cfg = Config(**sections)

    return cfg, configparser_cfg


@pytest.fixture
def cfg_tuple(request):
    """Returns a `config.Config` and a `configparser.ConfigParser` with testing defaults.
    Defaults can be overwritten with the `cfg_defaults` pytest mark.
    """
    # TODO Use iter_markers to be able to overwrite the config.
    # Make sure to iterate in order from closest to farthest.
    cfg_defaults_marker = request.node.get_closest_marker('cfg_defaults')
    cfg_defaults = cfg_defaults_marker.args[0] if cfg_defaults_marker else {}

    cfg, configparser_cfg = _get_test_config_tuple(cfg_defaults)
    yield cfg, configparser_cfg

    # Don't clean up directorys we didn't create ourselves
    if not cfg_defaults.get('data-storage', {}).get('docker-mount-base-dir', None):
        shutil.rmtree(cfg.data_storage.docker_mount_base_dir)
    if not cfg_defaults.get('data-storage', {}).get('firmware-file-storage-directory', None):
        shutil.rmtree(cfg.data_storage.firmware_file_storage_directory)


@pytest.fixture(autouse=True)
def patch_cfg(cfg_tuple):
    """This fixture will replace `config.cfg` and `config.configparser_cfg` with the default test config.
    See `cfg_tuple` on how to change defaults.
    """
    cfg, configparser_cfg = cfg_tuple
    mpatch = pytest.MonkeyPatch()
    # We only patch the private parts of the module.
    # This ensures that even, when `config.cfg` is imported before this fixture is executed we get
    # the patched config.
    mpatch.setattr('config._cfg', cfg)
    mpatch.setattr('config._configparser_cfg', configparser_cfg)
    yield

    mpatch.undo()

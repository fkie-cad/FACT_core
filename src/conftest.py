from __future__ import annotations

import dataclasses
import grp
import logging
import os
from configparser import ConfigParser
from tempfile import TemporaryDirectory
from typing import Type

import pytest
from pydantic.dataclasses import dataclass

import config
from analysis.PluginBase import AnalysisBasePlugin
from config import Config
from test.common_helper import CommonDatabaseMock
from test.conftest import merge_markers


@pytest.fixture
def _docker_mount_base_dir() -> str:
    docker_gid = grp.getgrnam('docker').gr_gid

    with TemporaryDirectory(prefix='fact-docker-mount-base-dir') as tmp_dir:
        os.chown(tmp_dir, -1, docker_gid)
        os.chmod(tmp_dir, 0o770)
        yield tmp_dir


@pytest.fixture
def _firmware_file_storage_directory() -> str:
    with TemporaryDirectory(prefix='fact-firmware-file-storage-directory') as tmp_dir:
        yield tmp_dir


def _get_test_config_tuple(
    firmware_file_storage_directory,
    docker_mount_base_dir,
    defaults: dict | None = None,
) -> tuple[Config, ConfigParser]:
    """Returns a tuple containing a `config.Config` instance and a `ConfigParser` instance.
    Both instances are equivalent and the latter is legacy only.
    The "docker-mount-base-dir" and "firmware-file-storage-directory" in the section "data-storage"
    are created and must be cleaned up manually.

    :arg defaults: Sections to overwrite
    """
    config.load()

    if 'docker-mount-base-dir' in defaults:
        raise ValueError('docker-mount-base-dir may not be changed with `@pytest.marker.cfg_defaults`')
    if 'firmware-file-storage-directory' in defaults:
        raise ValueError('firmware-file-storage-directory may not be changed with `@pytest.marker.cfg_defaults`')

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
            'redis-pw': '',
            'firmware-file-storage-directory': firmware_file_storage_directory,
            'user-database': 'sqlite:////media/data/fact_auth_data/fact_users.db',
            'password-salt': '1234',
            'structural-threshold': '40',  # TODO
            'temp-dir-path': '/tmp',
            'docker-mount-base-dir': docker_mount_base_dir,
        },
        'database': {
            'ajax-stats-reload-time': '10000',  # TODO
            'number-of-latest-firmwares-to-display': '10',
            'results-per-page': '10',
        },
        'default-plugins': {
            'default': '',
            'minimal': '',
        },
        'plugin-defaults': {
            'threads': 1,
        },
        'expert-settings': {
            'authentication': 'false',
            'block-delay': '0.1',
            'communication-timeout': '60',
            'intercom-poll-delay': '0.5',
            'nginx': 'false',
            'radare2-host': 'localhost',
            'ssdeep-ignore': '1',
            'throw-exceptions': 'true',  # Always throw exceptions to avoid miraculous timeouts in test cases
            'unpack-threshold': '0.8',
            'unpack_throttle_limit': '50',
            'unpacking_delay': '0.0',
        },
        'logging': {
            'logfile': '/tmp/fact_main.log',
            'loglevel': 'INFO',
        },
        'unpack': {
            'base-port': '9900',
            'max-depth': '10',
            'memory-limit': '2048',
            'threads': '4',
            'whitelist': '',
        },
        'statistics': {'max_elements_per_chart': '10'},
    }

    # Update recursively
    for section_name in defaults if defaults else {}:
        sections.setdefault(section_name, {}).update(defaults[section_name])

    configparser_cfg = ConfigParser()
    configparser_cfg.read_dict(sections)

    config._parse_dict(sections)
    cfg = Config(**sections)

    return cfg, configparser_cfg


# FIXME When configparser is not used anymore this should not be named cfg_tuple but rather cfg
@pytest.fixture
def cfg_tuple(request, _firmware_file_storage_directory, _docker_mount_base_dir):
    """Returns a ``config.Config`` and a ``configparser.ConfigParser`` with testing defaults.
    Defaults can be overwritten with the ``cfg_defaults`` pytest mark.
    """

    cfg_defaults = merge_markers(request, 'cfg_defaults', dict)

    cfg, configparser_cfg = _get_test_config_tuple(
        _firmware_file_storage_directory,
        _docker_mount_base_dir,
        cfg_defaults,
    )
    yield cfg, configparser_cfg


@pytest.fixture(autouse=True)
def patch_cfg(cfg_tuple):
    """This fixture will replace ``config.cfg`` and ``config.configparser_cfg`` with the default test config.
    See ``cfg_tuple`` on how to change defaults.
    """
    cfg, configparser_cfg = cfg_tuple
    mpatch = pytest.MonkeyPatch()
    # We only patch the private attributes of the module.
    # This ensures that even, when `config.cfg` is imported before this fixture is executed we get
    # the patched config.
    mpatch.setattr('config._cfg', cfg)
    mpatch.setattr('config._configparser_cfg', configparser_cfg)
    # Disallow code to load the actual, non-testing config
    # This only works if `load` was not imported by `from config import load`.
    # See doc comment of `load`.
    mpatch.setattr('config.load', lambda _=None: logging.warning('Code tried to call `config.load`. Ignoring.'))
    yield

    mpatch.undo()


@dataclass(config=dict(arbitrary_types_allowed=True))
class AnalysisPluginTestConfig:
    """A class configuring the :py:func:`analysis_plugin` fixture."""

    #: The class of the plugin to be tested. It will most probably be called ``AnalysisPlugin``.
    plugin_class: Type[AnalysisBasePlugin] = AnalysisBasePlugin
    #: Whether or not to start the workers (see ``AnalysisPlugin.start``)
    start_processes: bool = False
    #: Keyword arguments to be given to the ``plugin_class`` constructor.
    init_kwargs: dict = dataclasses.field(default_factory=dict)


@pytest.fixture
def analysis_plugin(request, monkeypatch, patch_cfg):
    """Returns an instance of an AnalysisPlugin.
    This fixture can be configured by the supplying an instance of ``AnalysisPluginTestConfig`` as marker of the same
    name.

    .. seealso::

        The documentation of :py:class:`AnalysisPluginTestConfig`

    If this fixture does not fit your needs (which normally should not be necessary) you can define a fixture like this:

    .. code-block::

        @pytest.fixture
        def my_fancy_plugin(analysis_plugin)
            # Make sure the marker is defined as expected
            assert isinstance(analysis_plugin, MyFancyPlugin)
            # Patch custom things
            analysis_plugin.db_interface = CustomDbMock()
            # Return the plugin instance
            yield analysis_plugin

    .. Note::

        If you want to set ``AnalysisPluginTestConfig.start_processes = True`` and want to modify plugin configuration
        like for example TIMEOUT you have to put the following in your test:

        .. code-block::

            @pytest.mark.AnalysisPluginTestConfig(
                plugin_class=MyFancyPlugin,
                # Actually don't start the processes in the fixture
                start_processes=False,
            )
            def my_fancy_test(analysis_plugin, monkeypatch):
                analysis_plugin.TIMEOUT = 0
                # Now start the worker
                analysis_plugin.start()
    """
    test_config = merge_markers(request, 'AnalysisPluginTestConfig', AnalysisPluginTestConfig)

    PluginClass = test_config.plugin_class

    # We don't want to actually start workers when testing, except for some special cases
    with monkeypatch.context() as mkp:
        if not test_config.start_processes:
            mkp.setattr(PluginClass, 'start', lambda _: None)
        plugin_instance = PluginClass(
            view_updater=CommonDatabaseMock(),
            **test_config.init_kwargs,
        )

    yield plugin_instance

    plugin_instance.shutdown()

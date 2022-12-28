from __future__ import annotations

import grp
import logging
import os
import shutil
import tempfile
from configparser import ConfigParser
from pathlib import Path

import pytest

import config
from analysis.PluginBase import AnalysisBasePlugin
from config import Config
from test.common_helper import CommonDatabaseMock
from test.conftest import merge_markers


def _create_docker_mount_base_dir() -> str:
    dir = tempfile.mkdtemp(prefix='fact-docker-mount-base-dir')
    docker_gid = grp.getgrnam('docker').gr_gid
    os.chown(dir, -1, docker_gid)
    os.chmod(dir, 0o770)

    return dir


def _get_test_config_tuple(defaults: dict | None = None) -> tuple[Config, ConfigParser]:
    """Returns a tuple containing a `config.Config` instance and a `ConfigParser` instance.
    Both instances are equivalent and the latter is legacy only.
    The "docker-mount-base-dir" and "firmware-file-storage-directory" in the section "data-storage"
    are created and must be cleaned up manually.

    :arg defaults: Sections to overwrite
    """
    config.load()

    docker_mount_base_dir = _create_docker_mount_base_dir()
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
        },
        'logging': {
            'logfile': '/tmp/fact_main.log',
            'loglevel': 'INFO',
        },
        'unpack': {'max-depth': '10', 'memory-limit': '2048', 'threads': '4', 'whitelist': ''},
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
def cfg_tuple(request):
    """Returns a ``config.Config`` and a ``configparser.ConfigParser`` with testing defaults.
    Defaults can be overwritten with the ``cfg_defaults`` pytest mark.
    """

    cfg_defaults = merge_markers(request, 'cfg_defaults', dict)

    cfg, configparser_cfg = _get_test_config_tuple(cfg_defaults)
    yield cfg, configparser_cfg

    # Don't clean up directorys we didn't create ourselves
    if not cfg_defaults.get('data-storage', {}).get('docker-mount-base-dir', None):
        shutil.rmtree(cfg.data_storage.docker_mount_base_dir)
    if not cfg_defaults.get('data-storage', {}).get('firmware-file-storage-directory', None):
        shutil.rmtree(cfg.data_storage.firmware_file_storage_directory)


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


@pytest.fixture
def analysis_plugin(request, monkeypatch, patch_cfg):
    """Returns an instance of an AnalysisPlugin.
    The following pytest markers affect this fixture:

    * AnalysisPluginClass: The plugin class type. Must be a class derived from ``AnalysisBasePlugin``.
      The marker has to be set with ``@pytest.mark.with_args`` to work around pytest
      `link weirdness <https://docs.pytest.org/en/7.1.x/example/markers.html#passing-a-callable-to-custom-markers>`.
    * plugin_start_worker: If set the AnalysisPluginClass.start_worker method will NOT be overwritten.
      If not set the method is overwritten by a stub that does nothing.
    * plugin_init_kwargs: Additional keyword arguments that shall be passed to the ``AnalysisPluginClass`` constructor

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

        If you use the ``plugin_start_worker`` marker and want to modify plugin configuration like for example TIMEOUT
        you have to put the following in your test:

        .. code-block::

            @pytest.mark.AnalysisPluginClass.with_args(MyFancyPlugin)
            # Don't use `plugin_start_worker`
            def my_fancy_test(analysis_plugin, monkeypatch):
                # Undo the patching of MyFancyPlugin.start_worker
                monkeypatch.undo()
                analysis_plugin.TIMEOUT = 0
                # Now start the worker
                analysis_plugin.start_worker()
    """
    # IMPORTANT, READ BEFORE EDITING:
    # This fixture uses the default monkeypatch fixture.
    # The reason for this is that tests shall be able to undo the patching of `AnalysisPluginClass.start_worker`.
    # If you want to monkeypatch anything other in this fixture don't use the default monkeypatch fixture but rather
    # create a new instance.
    #
    # See also: The note in the doc comment.

    plugin_class_marker = request.node.get_closest_marker('AnalysisPluginClass')
    assert plugin_class_marker, '@pytest.mark.AnalysisPluginClass has to be defined'
    PluginClass = plugin_class_marker.args[0]
    assert issubclass(
        PluginClass, AnalysisBasePlugin
    ), f'{PluginClass.__name__} is not a subclass of {AnalysisBasePlugin.__name__}'

    # We don't want to actually start workers when testing, except for some special cases
    plugin_start_worker_marker = request.node.get_closest_marker('plugin_start_worker')
    if not plugin_start_worker_marker:
        monkeypatch.setattr(PluginClass, 'start_worker', lambda _: None)

    plugin_init_kwargs_marker = request.node.get_closest_marker('plugin_init_kwargs')
    kwargs = plugin_init_kwargs_marker.kwargs if plugin_init_kwargs_marker else {}

    plugin_instance = PluginClass(
        view_updater=CommonDatabaseMock(),
        **kwargs,
    )
    yield plugin_instance

    plugin_instance.shutdown()

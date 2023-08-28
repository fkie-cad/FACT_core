from __future__ import annotations

import grp
import logging
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Type, Union

import pytest
from pydantic import BaseModel, Field
from pydantic.v1 import ConfigDict
from pydantic.v1.utils import deep_update

import config
from analysis.PluginBase import AnalysisBasePlugin
from analysis.plugin import AnalysisPluginV0
from test.common_helper import CommonDatabaseMock
from test.conftest import merge_markers


@pytest.fixture
def docker_mount_base_dir() -> str:
    docker_gid = grp.getgrnam('docker').gr_gid

    with TemporaryDirectory(prefix='fact-docker-mount-base-dir') as tmp_dir:
        os.chown(tmp_dir, -1, docker_gid)
        Path(tmp_dir).chmod(0o770)
        yield tmp_dir


@pytest.fixture
def _firmware_file_storage_directory() -> str:  # noqa: PT005
    with TemporaryDirectory(prefix='fact-firmware-file-storage-directory') as tmp_dir:
        yield tmp_dir


@pytest.fixture
def common_config(request, docker_mount_base_dir) -> config.Common:
    overwrite_config = merge_markers(request, 'common_config_overwrite', dict)

    if 'docker_mount_base_dir' in overwrite_config:
        raise ValueError('docker-mount-base-dir may not be changed with `@pytest.marker.common_config_overwrite`')

    config.load()
    test_config = {
        'temp_dir_path': '/tmp',
        'docker_mount_base_dir': docker_mount_base_dir,
        'redis': dict(
            {
                'fact_db': config.common.redis.test_db,
                'test_db': config.common.redis.test_db,
                'host': config.common.redis.host,
                'port': config.common.redis.port,
                # FIXME Omitting the password might be wrong
            },
            **{
                'password': config.common.redis.password,
            }
            if config.common.redis.password is not None
            else {},
        ),
        'logging': {
            # Use different logfiles to prevent writing in the actual logfiles
            'file_backend': '/tmp/fact_tests_backend.log',
            'file_frontend': '/tmp/fact_tests_frontend.log',
            'file_database': '/tmp/fact_tests_database.log',
            'level': 'DEBUG',  # Use lowest loglevel for tests
        },
        'postgres': {
            'server': config.common.postgres.server,
            'port': config.common.postgres.port,
            'database': config.common.postgres.test_database,
            'test_database': config.common.postgres.test_database,
            'ro_user': config.common.postgres.ro_user,
            'ro_pw': config.common.postgres.ro_pw,
            'rw_user': config.common.postgres.rw_user,
            'rw_pw': config.common.postgres.rw_pw,
            'del_user': config.common.postgres.del_user,
            'del_pw': config.common.postgres.del_pw,
            'admin_user': config.common.postgres.admin_user,
            'admin_pw': config.common.postgres.admin_pw,
        },
        'analysis_preset': {
            'default': {
                'name': 'default',
                'plugins': [],
            },
            'minimal': {
                'name': 'minimal',
                'plugins': [],
            },
        },
    }

    test_config = deep_update(test_config, overwrite_config)

    return config.Common(**test_config)


@pytest.fixture
def backend_config(request, common_config, _firmware_file_storage_directory) -> config.Backend:
    overwrite_config = merge_markers(request, 'backend_config_overwrite', dict)

    test_config = {
        'firmware_file_storage_directory': _firmware_file_storage_directory,
        'block_delay': 0.1,
        'ssdeep_ignore': 1,
        'intercom_poll_delay': 1.0,
        'throw_exceptions': True,  # Always throw exceptions to avoid miraculous timeouts in test cases
        'plugin_defaults': {'processes': 1},
        'unpacking': {
            'processes': 2,
            'whitelist': [],
            'max_depth': 8,
            'memory_limit': 2048,
            'throttle_limit': 50,
            'delay': 0.0,
            'base_port': 9900,
        },
        'plugin': {
            'cpu_architecture': {'name': 'cpu_architecture', 'processes': 4},
            'cve_lookup': {'name': 'cve_lookup', 'processes': 2},
        },
    }

    test_config.update(common_config.model_dump())
    test_config = deep_update(test_config, overwrite_config)

    return config.Backend(**test_config)


@pytest.fixture
def frontend_config(request, common_config) -> config.Frontend:
    overwrite_config = merge_markers(request, 'frontend_config_overwrite', dict)
    test_config = {
        'results_per_page': 10,
        'number_of_latest_firmwares_to_display': 10,
        'ajax_stats_reload_time': 10000,
        'max_elements_per_chart': 10,
        'radare2_url': 'http://localhost:8000',
        'communication_timeout': 60,
        'authentication': {
            'enabled': False,
            'user_database': 'sqlite:////media/data/fact_auth_data/fact_users.db',
            'password_salt': '5up3r5tr0n6_p455w0rd_5417',
        },
    }

    test_config.update(common_config.model_dump())
    test_config = deep_update(test_config, overwrite_config)

    return config.Frontend(**test_config)


@pytest.fixture(autouse=True)
def patch_config(monkeypatch, common_config, backend_config, frontend_config):  # noqa: PT004
    """This fixture will replace :py:data`config.common`, :py:data:`config.backend` and :py:data:`config.frontend`
    with the default test config.

    Defaults in the test config can be overwritten with the markers ``backend_config_overwrite``,
    ``frontend_config_overwrite`` and ``common_config_overwrite``.
    These three markers accept a single argument of the type ``dict``.
    When using ``backend_config_overwrite`` the dictionary has to contain valid keyword arguments for
    :py:class:`Backend`.
    """
    # We only patch the private attributes of the module.
    # This ensures that even, when e.g. `config.common` is imported before this fixture is executed we get
    # the patched config.
    monkeypatch.setattr('config._common', common_config)
    monkeypatch.setattr('config._backend', backend_config)
    monkeypatch.setattr('config._frontend', frontend_config)
    # Disallow code to load the actual, non-testing config
    # This only works if `load` was not imported by `from config import load`.
    # See doc comment of `load`.
    monkeypatch.setattr('config.load', lambda _=None: logging.warning('Code tried to call `config.load`. Ignoring.'))


class AnalysisPluginTestConfig(BaseModel):
    """A class configuring the :py:func:`analysis_plugin` fixture."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    #: The class of the plugin to be tested. It will most probably be called ``AnalysisPlugin``.
    plugin_class: Union[Type[AnalysisBasePlugin], Type[AnalysisPluginV0]] = AnalysisBasePlugin
    #: Whether or not to start the workers (see ``AnalysisPlugin.start``).
    #: Not supported for AnalysisPluginV0
    start_processes: bool = False
    #: Keyword arguments to be given to the ``plugin_class`` constructor.
    #: Not supported for AnalysisPluginV0
    init_kwargs: dict = Field(default_factory=dict)


@pytest.fixture
def analysis_plugin(request, patch_config):  # noqa: ARG001
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

    # FIXME now with AnalysisPluginV0 analysis plugins became way simpler
    # We might want to delete everything from AnalysisPluginTestConfig in the future
    PluginClass = test_config.plugin_class  # noqa: N806
    if issubclass(PluginClass, AnalysisPluginV0):
        assert (
            test_config.init_kwargs == {}
        ), 'AnalysisPluginTestConfig.init_kwargs must be empty for AnalysisPluginV0 instances'
        assert (
            not test_config.start_processes
        ), 'AnalysisPluginTestConfig.start_processes cannot be True for AnalysisPluginV0 instances'

        yield PluginClass()

    elif issubclass(PluginClass, AnalysisBasePlugin):
        plugin_instance = PluginClass(
            view_updater=CommonDatabaseMock(),
            **test_config.init_kwargs,
        )

        # We don't want to actually start workers when testing, except for some special cases
        if test_config.start_processes:
            plugin_instance.start()

        yield plugin_instance

        plugin_instance.shutdown()

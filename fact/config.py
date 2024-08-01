from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

import toml
from pydantic import BaseModel, ConfigDict, field_validator
from werkzeug.local import LocalProxy

_backend = None
#: Proxy to an instance of :py:class:`Backend`
#: May only be used in parts of the code that are backend code.
backend: Backend = LocalProxy(lambda: _backend)

_frontend = None
#: Proxy to an instance of :py:class:`Frontend`
#: May only be used in parts of the code that are frontend code.
frontend: Frontend = LocalProxy(lambda: _frontend)

_common = None
#: Proxy to an instance of :py:class:`Common`
#: May only be used in parts of the code that are neither frontend nor backend code.
common: Common = LocalProxy(lambda: _common)


class Common(BaseModel):
    class Postgres(BaseModel):
        model_config = ConfigDict(extra='forbid')

        server: str
        port: int
        database: str
        test_database: str

        rw_user: str
        rw_pw: str

        ro_user: str
        ro_pw: str

        del_user: str
        del_pw: str

        admin_user: str
        admin_pw: str

    class Redis(BaseModel):
        model_config = ConfigDict(extra='forbid')

        fact_db: int
        test_db: int
        host: str
        port: int
        password: Optional[str] = None

    class Logging(BaseModel):
        model_config = ConfigDict(extra='forbid')

        file_backend: str = '/tmp/fact_backend.log'
        file_frontend: str = '/tmp/fact_frontend.log'
        file_database: str = '/tmp/fact_database.log'
        level: str = 'WARNING'

        @field_validator('level')
        @classmethod
        def _validate_level(cls, value):
            if isinstance(logging.getLevelName(value), str):
                raise ValueError(f'The "loglevel" {value} is not a valid loglevel.')

            return value

    class AnalysisPreset(BaseModel):
        model_config = ConfigDict(extra='forbid')

        name: str
        plugins: List[str]

    postgres: Common.Postgres
    redis: Common.Redis
    logging: Common.Logging

    analysis_preset: Dict[str, Common.AnalysisPreset]

    temp_dir_path: str = '/tmp'
    docker_mount_base_dir: str


class Frontend(Common):
    model_config = ConfigDict(extra='forbid')

    class Authentication(BaseModel):
        model_config = ConfigDict(extra='forbid')

        enabled: bool
        user_database: str
        password_salt: str

    communication_timeout: int = 60

    authentication: Frontend.Authentication

    results_per_page: int
    number_of_latest_firmwares_to_display: int = 10
    ajax_stats_reload_time: int

    max_elements_per_chart: int = 10

    radare2_url: str


class Backend(Common):
    model_config = ConfigDict(extra='forbid')

    class Unpacking(BaseModel):
        processes: int
        whitelist: list
        max_depth: int
        memory_limit: int = 2048

        throttle_limit: int

        delay: float
        base_port: int

    class PluginDefaults(BaseModel):
        processes: int

    class Plugin(BaseModel):
        model_config = ConfigDict(extra='allow')

        name: str

    scheduling_worker_count: int = 4
    collector_worker_count: int = 2

    unpacking: Backend.Unpacking

    firmware_file_storage_directory: str

    block_delay: float
    ssdeep_ignore: int

    intercom_poll_delay: float

    throw_exceptions: bool

    plugin_defaults: Backend.PluginDefaults
    plugin: Dict[str, Backend.Plugin]

    @field_validator('temp_dir_path')
    @classmethod
    def _validate_temp_dir_path(cls, value):
        if not Path(value).exists():
            raise ValueError('The "temp-dir-path" does not exist.')
        return value


def load(path: str | None = None):
    """Load the config file located at ``path``.
    The file must be a toml file and is read into instances of :py:class:`~config.Backend`,
    :py:class:`~config.Frontend` and :py:class:`~config.Common`.

    These instances can be accessed via ``config.backend`` after calling this function.

    .. important::
        This function may not be imported by ``from fact.config import load``.
        It may only be imported by ``from fact import config`` and then used by ``config.load()``.
        The reason is that testing code can't patch this function if it was already imported.
        When you only import the ``config`` module the ``load`` function will be looked up at runtime.
        See `this blog entry <https://alexmarandon.com/articles/python_mock_gotchas/>`_ for some more information.
    """
    Common.model_rebuild()
    Backend.model_rebuild()
    Frontend.model_rebuild()
    if path is None:
        path = Path(__file__).parent / 'config/fact-core-config.toml'

    with open(path, encoding='utf8') as f:  # noqa: PTH123
        cfg = toml.load(f)

    _replace_hyphens_with_underscores(cfg)

    backend_dict = cfg['backend']
    frontend_dict = cfg['frontend']
    common_dict = cfg['common']

    preset_list = common_dict.pop('analysis_preset', [])
    preset_dict = {}
    for preset in preset_list:
        p = Common.AnalysisPreset(**preset)
        preset_dict[p.name] = p.model_dump()

    common_dict['analysis_preset'] = preset_dict

    plugin_list = backend_dict.pop('plugin', [])
    plugin_dict = {}
    for plugin in plugin_list:
        p = Backend.Plugin(**plugin)
        plugin_dict[p.name] = p.model_dump()

    backend_dict['plugin'] = plugin_dict

    if 'common' not in cfg:
        raise ValueError('The common section MUST be specified')

    global _common  # noqa: PLW0603
    if 'common' in cfg:
        _common = Common(**common_dict)

    global _backend  # noqa: PLW0603
    if 'backend' in cfg:
        _backend = Backend(**backend_dict, **common_dict)

    global _frontend  # noqa: PLW0603
    if 'frontend' in cfg:
        _frontend = Frontend(**frontend_dict, **common_dict)


def _replace_hyphens_with_underscores(dictionary):
    if not isinstance(dictionary, dict):
        return

    for key in list(dictionary.keys()):
        _replace_hyphens_with_underscores(dictionary[key])
        value = dictionary.pop(key)
        dictionary[key.replace('-', '_')] = value

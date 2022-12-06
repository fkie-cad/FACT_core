from __future__ import annotations

import configparser
from configparser import ConfigParser
from pathlib import Path

from pydantic import BaseModel, Extra
from werkzeug.local import LocalProxy

# pylint: disable=invalid-name
_cfg = None
cfg: 'Config' = LocalProxy(lambda: _cfg)

_configparser_cfg = None
# For transitioning between using ConfigParser and this module.
# Use cfg in new code
configparser_cfg = LocalProxy(lambda: _configparser_cfg)


class _PydanticConfigExtraForbid:
    # FIXME this should be replaced by class kwargs (extra=Extra.forbid)
    # Sphinx autodoc will complain about unknown kwargs
    extra = Extra.forbid


class _PydanticConfigExtraAllow:
    extra = Extra.allow


class DataStorage(BaseModel):
    Config = _PydanticConfigExtraForbid
    postgres_server: str
    postgres_port: int
    postgres_database: str
    postgres_test_database: str

    postgres_ro_user: str
    postgres_ro_pw: str

    postgres_rw_user: str
    postgres_rw_pw: str

    postgres_del_user: str
    postgres_del_pw: str

    postgres_admin_user: str
    postgres_admin_pw: str

    redis_fact_db: str
    redis_test_db: str
    redis_host: str
    redis_port: int

    firmware_file_storage_directory: str

    user_database: str
    password_salt: str

    structural_threshold: int

    temp_dir_path: str = '/tmp'
    docker_mount_base_dir: str


class Logging(BaseModel):
    Config = _PydanticConfigExtraForbid
    logfile: str
    loglevel: str


class Unpack(BaseModel):
    Config = _PydanticConfigExtraForbid
    threads: int
    whitelist: list
    max_depth: int
    memory_limit: int = 2048


class DefaultPlugins(BaseModel):
    Config = _PydanticConfigExtraAllow


class Database(BaseModel):
    Config = _PydanticConfigExtraForbid
    results_per_page: int
    number_of_latest_firmwares_to_display: int = 10
    ajax_stats_reload_time: int


class Statistics(BaseModel):
    Config = _PydanticConfigExtraForbid
    max_elements_per_chart: int = 10


class ExpertSettings(BaseModel):
    Config = _PydanticConfigExtraForbid
    block_delay: float
    ssdeep_ignore: int
    communication_timeout: int = 60
    unpack_threshold: float
    unpack_throttle_limit: int
    throw_exceptions: bool
    authentication: bool
    nginx: bool
    intercom_poll_delay: float
    radare2_host: str


# We need to allow extra here since we don't know what plugins will be loaded
class Config(BaseModel):
    Config = _PydanticConfigExtraAllow
    data_storage: DataStorage
    logging: Logging
    unpack: Unpack
    default_plugins: DefaultPlugins
    database: Database
    statistics: Statistics
    expert_settings: ExpertSettings


def _parse_dict(sections):
    """
    Parses the section of the config file given as a dictionary.
    The following things are parsed:
        * Entries whose value is an empty string just are removed.
        * Comma separated lists are changed to actual lists.
    """
    # hyphens may not be contained in identifiers
    # plugin names may also not contain hyphens, so this is fine
    _replace_hyphens_with_underscores(sections)

    sections['unpack']['whitelist'] = parse_comma_separated_list(sections['unpack']['whitelist'])
    for plugin_set in sections['default_plugins']:
        sections['default_plugins'][plugin_set] = parse_comma_separated_list(sections['default_plugins'][plugin_set])

    for section_name, section in sections.items():
        # The section name is not plugin configuration.
        # We can't use the pydantic model here since plugin sections are all extra sections.
        if section_name in Config.__fields__:
            continue
        section['mime_whitelist'] = parse_comma_separated_list(section.get('mime_whitelist', ''))
        section['mime_blacklist'] = parse_comma_separated_list(section.get('mime_blacklist', ''))

    # This must be done last since empty values e.g. in the default-plugins section might be interpreted otherwise if
    # left empty.
    for section_name, section in sections.items():
        for entry, value in section.copy().items():
            if value == '':
                sections[section_name].pop(entry)


def load(path: str | None = None):
    # pylint: disable=global-statement
    """Load the config file located at ``path``.
    The file must be an ini file and is read into an `config.Config` instance.
    This instance can be accessed with ``config.cfg`` after calling this function.
    For legacy code that needs a ``ConfigParser`` instance ``config.configparser_cfg`` is provided.

    .. important::
        This function may not be imported by ``from config import load``.
        It may only be imported by ``import config`` and then used by ``config.load()``.
        The reason is that testing code can't patch this function if it was already imported.
        When you only import the ``config`` module the ``load`` function will be looked up at runtime.
        See `this blog entry <https://alexmarandon.com/articles/python_mock_gotchas/>`_ for some more information.
    """
    if path is None:
        path = Path(__file__).parent / 'config/main.cfg'

    parser = ConfigParser()
    with open(path, encoding='utf8') as f:
        parser.read_file(f)

    parsed_sections = {key: dict(section) for key, section in parser.items() if key != configparser.DEFAULTSECT}
    _parse_dict(parsed_sections)
    global _cfg
    global _configparser_cfg
    _configparser_cfg = parser
    _cfg = Config(**parsed_sections)

    _verify_config(_cfg)


def _verify_config(config: Config):
    """Analyze the config for simple errors that a sysadmin might make."""
    if not Path(config.data_storage.temp_dir_path).exists():
        raise ValueError('The "temp-dir-path" as specified in section "data-storage" does not exist.')


def _replace_hyphens_with_underscores(sections):
    for section in list(sections.keys()):
        for key in list(sections[section].keys()):
            sections[section][key.replace('-', '_')] = sections[section].pop(key)
        sections[section.replace('-', '_')] = sections.pop(section)


def parse_comma_separated_list(list_string):
    return [item.strip() for item in list_string.split(',') if item != '']

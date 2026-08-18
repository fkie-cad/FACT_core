import config
from version import __VERSION__


def auth_is_enabled() -> bool:
    return config.frontend.authentication.enabled


def get_fact_version() -> str:
    return __VERSION__

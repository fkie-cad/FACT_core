from typing import NamedTuple


class PluginData(NamedTuple):
    description: str
    mandatory: bool
    presets: dict
    version: str
    dependencies: list
    blacklist: list
    whitelist: list
    worker_count: int
    tooltip: str

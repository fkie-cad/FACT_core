from __future__ import annotations

from werkzeug.local import LocalProxy

from config import configparser_cfg

# Expose singleton instances of all storage related Classes.

_binary_service = None
binary_service: 'BinaryService' = LocalProxy(lambda: _binary_service)

_binary_service_interface = None
binary_service_interface: 'BinaryServiceDbInterface' = LocalProxy(lambda: _binary_service_interface)

_fsorganizer = None
fsorganizer: 'FSOrganizer' = LocalProxy(lambda: _fsorganizer)

_redis_interface = None
redis_interface: 'RedisInterface' = LocalProxy(lambda: _redis_interface)

_ro_interface = None
ro_interface = LocalProxy(lambda: _ro_interface)

_rw_interface = None
rw_interface = LocalProxy(lambda: _rw_interface)

_admin_interface = None
admin_interface = LocalProxy(lambda: _admin_interface)


def load():
    """
    """
    # Import here to prevent circular import

    # TODO: find out a way to handle dependenies
    #       e.g. BinaryService depends on BinaryServiceDbInterface
    assert configparser_cfg is not None, 'You must call `config.load_config` before `storage.globals.load_globals`'

    from storage.binary_service import BinaryService
    global _binary_service
    _binary_service = BinaryService(configparser_cfg)

    from storage.binary_service import BinaryServiceDbInterface
    global _binary_service_interface
    _binary_service_interface = BinaryServiceDbInterface(configparser_cfg)

    from storage.fsorganizer import FSOrganizer
    global _fsorganizer
    _fsorganizer = FSOrganizer(configparser_cfg)

    from storage.redis_interface import RedisInterface
    global _redis_interface
    _redis_interface = RedisInterface(configparser_cfg)

    from storage.db_interface_base import ReadOnlyDbInterface
    global _ro_interface
    _ro_interface = ReadOnlyDbInterface(configparser_cfg)

    from storage.db_interface_base import ReadWriteDbInterface
    global _rw_interface
    _rw_interface = ReadWriteDbInterface(configparser_cfg)

    from storage.db_interface_admin import AdminDbInterface
    global _admin_interface
    _admin_interface = AdminDbInterface(configparser_cfg)

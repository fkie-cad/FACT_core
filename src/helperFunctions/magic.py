"""This is a wrapper around pymagic.
It aims to provide the same API but with the ability to load multiple magic
files in the default api.
"""
from __future__ import annotations

import os
from os import PathLike

import magic as pymagic

from helperFunctions.fileSystem import get_src_dir

# On ubuntu this is provided by the libmagic-mgc package
_default_magic = os.getenv('MAGIC', '/usr/lib/file/magic.mgc')
_fact_magic = f'{get_src_dir()}/bin/firmware.mgc'
_internal_symlink_magic = f'{get_src_dir()}/bin/internal_symlink_magic.mgc'
_magic_file = f'{_internal_symlink_magic}:{_fact_magic}:{_default_magic}'

_instances = {}


def _get_magic_instance(**kwargs):
    """Returns an instance of pymagic.Maigc"""
    # Dicts are not hashable but sorting and creating a tuple is a valid hash
    key = hash(tuple(sorted(kwargs.items())))
    instance = _instances.get(key)
    if instance is None:
        instance = _instances[key] = pymagic.Magic(**kwargs)
    return instance


def from_file(filename: bytes | str | PathLike, magic_file: str | None = _magic_file, **kwargs) -> str:
    """Like pymagic's ``magic.from_file`` but it accepts all keyword arguments
    that ``magic.Magic`` accepts.
    """
    m = _get_magic_instance(magic_file=magic_file, **kwargs)
    return m.from_file(filename)


def from_buffer(buf: bytes | str, magic_file: str | None = _magic_file, **kwargs) -> str:
    """Like pymagic's ``magic.from_buffer`` but it accepts all keyword arguments
    that ``magic.Magic`` accepts.
    """
    instance = _get_magic_instance(magic_file=magic_file, **kwargs)
    return instance.from_buffer(buf)

"""This is a wrapper around pymagic.
It aims to provide the same API but with the ability to load multiple magic
files in the default api.
"""
import magic as pymagic
import os

from helperFunctions.fileSystem import get_src_dir

# On ubuntu this is provided by the libmagic-mgc package
_default_magic = os.getenv('MAGIC', '/usr/lib/file/magic.mgc')
_fact_magic = f'{get_src_dir()}/bin/firmware.mgc'
_internal_symlink_magic = f'{get_src_dir()}/bin/internal_symlink.mgc'
_magic_file = f'{_internal_symlink_magic}:{_fact_magic}:{_default_magic}'

_instances = {}


def _get_magic_instance(**kwargs):
    """Returns an instance of pymagic.Maigc"""
    # Dicts are not hashable but sorting and creating a tuple is a valid hash
    key = hash(tuple(sorted(kwargs.items())))
    i = _instances.get(key)
    if i is None:
        i = _instances[key] = pymagic.Magic(**kwargs)
    return i


def from_file(filename, magic_file=_magic_file, **kwargs) -> str:
    """Like pymagic's ``magic.from_file`` but it accepts all keyword arguments
    that ``magic.Magic`` accepts.
    """
    m = _get_magic_instance(magic_file=magic_file, **kwargs)
    return m.from_file(filename)


def from_buffer(filename, magic_file=_magic_file, **kwargs) -> str:
    """Like pymagic's ``magic.from_buffer`` but it accepts all keyword arguments
    that ``magic.Magic`` accepts.
    """
    m = _get_magic_instance(magic_file=magic_file, **kwargs)
    return m.from_file(filename)

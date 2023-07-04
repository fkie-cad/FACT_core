"""This is a wrapper around pymagic.
It aims to provide the same API but with the ability to load multiple magic
files in the default api.
"""
import magic as pymagic
from ctypes import c_int, c_char_p

from helperFunctions.fileSystem import get_src_dir

_magic_getpath = pymagic.libmagic.magic_getpath
_magic_getpath.restype = c_char_p
_magic_getpath.argtypes = [c_char_p, c_int]

_sys_magic = _magic_getpath(None, 1)
_fact_magic = f'{get_src_dir()}/bin/fact.mgc'

_magic_by_mime = {}


def _get_magic(mime: bool) -> pymagic.Magic:
    if mime not in _magic_by_mime:
        _magic_by_mime[mime] = pymagic.Magic(
            mime=mime,
            magic_file=f'{_fact_magic}:{_sys_magic}',
        )

    return _magic_by_mime[mime]


def from_file(filename, mime=False) -> str:
    """A wrapper for pymagic's ``magic.Magic.from_file``"""
    return _get_magic(mime).from_file(filename)


def from_buffer(filename, mime=False) -> str:
    """A wrapper for pymagic's ``magic.Magic.from_buffer``"""
    return _get_magic(mime).from_buffer(filename)

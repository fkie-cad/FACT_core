from tempfile import _TemporaryFileWrapper
from typing import TypeVar, TypeAlias


KT = TypeVar('KT', str, tuple, bytes)  # generic key type
VT = TypeVar('VT')  # generic value type

# NamedTemporaryFile is actually a function that returns an instance of class _TemporaryFileWrapper, so it can't be
# used for type hinting
TmpFile: TypeAlias = _TemporaryFileWrapper

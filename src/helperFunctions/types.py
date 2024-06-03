from __future__ import annotations

from multiprocessing.sharedctypes import Synchronized, SynchronizedArray
from tempfile import _TemporaryFileWrapper
from typing import TypeVar

# FixMe: add TypeAlias type hint when FACT supports Python>=3.10 only (31 Oct 2025)
# a UID (unique identifier) "{sha256 hash}_{file size in bytes}" for a byte string (i.e. the contents of a file)
UID = str

KT = TypeVar('KT', str, tuple, bytes)  # generic key type
VT = TypeVar('VT')  # generic value type

# NamedTemporaryFile is actually a function that returns an instance of class _TemporaryFileWrapper, so it can't be
# used for type hinting
TmpFile = _TemporaryFileWrapper

# multiprocessing.Value returns "SynchronizedBase[Any]" which has no attribute "value". This is a known bug in
# mypy, see https://github.com/python/typeshed/issues/8799 -> ignore assignment and treat as Synchronized
MpValue = Synchronized
MpArray = SynchronizedArray

# comparison ID: Represents one comparison between two or more firmwares.
# Consists of UIDs with semicolons in-between (e.g. "uid1;uid2;...")
CompId = str

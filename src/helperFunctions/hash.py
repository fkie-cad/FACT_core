from __future__ import annotations

from hashlib import new
from typing import TYPE_CHECKING

import tlsh

from helperFunctions.data_conversion import make_bytes

if TYPE_CHECKING:
    from typing import Any, AnyStr

ELF_MIME_TYPES = [
    'application/x-executable',
    'application/x-object',
    'application/x-pie-executable',
    'application/x-sharedlib',
]


def get_hash(hash_function: str, binary: AnyStr) -> str:
    """
    Hashes binary with hash_function.

    :param hash_function: The hash function to use. See hashlib for more
    :param binary: The data to hash, either as string or array of Integers
    :return: The hash as hex string
    """
    raw_hash = new(hash_function)
    raw_hash.update(make_bytes(binary))
    return raw_hash.hexdigest()


def get_sha256(code: AnyStr) -> str:
    return get_hash('sha256', code)


def get_md5(code: AnyStr) -> str:
    return get_hash('md5', code)


def get_tlsh_comparison(first: str, second: str) -> int:
    return tlsh.diff(first, second)


def normalize_lief_items(functions: list[Any]) -> list[str]:
    """
    Shorthand to convert a list of objects to a list of strings
    """
    return [str(function) for function in functions]

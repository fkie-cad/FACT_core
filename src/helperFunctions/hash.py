from __future__ import annotations

from hashlib import new

import tlsh

from helperFunctions.data_conversion import make_bytes


def get_hash(hash_function: str, binary: bytes | str) -> str:
    """
    Hashes binary with hash_function.

    :param hash_function: The hash function to use. See hashlib for more
    :param binary: The data to hash, either as string or array of Integers
    :return: The hash as hex string
    """
    raw_hash = new(hash_function)
    raw_hash.update(make_bytes(binary))
    return raw_hash.hexdigest()


def get_sha256(code: bytes | str) -> str:
    return get_hash('sha256', code)


def get_md5(code: bytes | str) -> str:
    return get_hash('md5', code)


def get_tlsh_comparison(first, second):
    return tlsh.diff(first, second)

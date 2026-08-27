from __future__ import annotations

import hashlib
import sys
from hashlib import new
from typing import TYPE_CHECKING

import tlsh

from helperFunctions.data_conversion import make_bytes

if TYPE_CHECKING:
    from pathlib import Path


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


def get_sha256_for_path(path: Path) -> str:
    with path.open('rb') as fp:
        if sys.version_info >= (3, 11):
            digest = hashlib.file_digest(fp, 'sha256')
        else:
            # FixMe: remove when Python3.10 is EoL; hashlib.file_digest reads the file memory efficiently in chunks
            #        here we have to do this manually
            digest = hashlib.sha256()
            while chunk := fp.read(2**20):
                digest.update(chunk)
    return digest.hexdigest()


def get_md5(code: bytes | str) -> str:
    return get_hash('md5', code)


def get_tlsh_comparison(first: str, second: str) -> int:
    return tlsh.diff(first, second)

from __future__ import annotations

import contextlib
import logging
import sys
from hashlib import md5, new
from typing import TYPE_CHECKING

import lief
import ssdeep
import tlsh

from helperFunctions.data_conversion import make_bytes

if TYPE_CHECKING:
    from objects.file import FileObject

ELF_MIME_TYPES = [
    'application/x-executable',
    'application/x-object',
    'application/x-pie-executable',
    'application/x-sharedlib',
]


def get_hash(hash_function, binary):
    """
    Hashes binary with hash_function.

    :param hash_function: The hash function to use. See hashlib for more
    :param binary: The data to hash, either as string or array of Integers
    :return: The hash as hexstring
    """
    binary = make_bytes(binary)
    raw_hash = new(hash_function)
    raw_hash.update(binary)
    return raw_hash.hexdigest()


def get_sha256(code):
    return get_hash('sha256', code)


def get_md5(code):
    return get_hash('md5', code)


def get_ssdeep(code):
    binary = make_bytes(code)
    raw_hash = ssdeep.Hash()
    raw_hash.update(binary)
    return raw_hash.digest()


def get_tlsh(code):
    tlsh_hash = tlsh.hash(make_bytes(code))
    return tlsh_hash if tlsh_hash != 'TNULL' else ''


def get_tlsh_comparison(first, second):
    return tlsh.diff(first, second)


def get_imphash(file_object: FileObject) -> str | None:
    """
    Generates and returns the md5 hash of the (sorted) imported functions of an ELF file represented by `file_object`.
    Returns `None` if there are no imports or if an exception occurs.

    :param file_object: The FileObject of which the imphash shall be computed
    """
    if _is_elf_file(file_object):
        try:
            with _suppress_stdout():
                functions = [f.name for f in lief.ELF.parse(file_object.file_path).imported_functions]
            if functions:
                return md5(','.join(sorted(functions)).encode()).hexdigest()
        except Exception:
            logging.exception(f'Could not compute imphash for {file_object.file_path}')
    return None


def _is_elf_file(file_object: FileObject) -> bool:
    return file_object.processed_analysis['file_type']['result']['mime'] in ELF_MIME_TYPES


def normalize_lief_items(functions):
    """
    Shorthand to convert a list of objects to a list of strings
    """
    return [str(function) for function in functions]


class _StandardOutWriter:
    def write(self, _):
        pass


@contextlib.contextmanager
def _suppress_stdout():
    """A context manager that suppresses any output to stdout and stderr."""
    writer = _StandardOutWriter()

    stdout, stderr = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = writer, writer  # type: ignore[assignment]

    yield

    sys.stdout, sys.stderr = stdout, stderr

import logging
from hashlib import md5, new

import lief
import ssdeep
import tlsh

from helperFunctions.dataConversion import make_bytes
from helperFunctions.debug import suppress_stdout


def get_hash(hash_function, binary):
    binary = make_bytes(binary)
    raw_hash = new(hash_function)
    raw_hash.update(binary)
    string_hash = raw_hash.hexdigest()
    return string_hash


def get_sha256(code):
    return get_hash('sha256', code)


def get_md5(code):
    return get_hash('md5', code)


def get_ssdeep(code):
    binary = make_bytes(code)
    raw_hash = ssdeep.Hash()
    raw_hash.update(binary)
    return raw_hash.digest()


def get_ssdeep_comparison(first, second):
    return ssdeep.compare(first, second)


def get_tlsh(code):
    return tlsh.hash(make_bytes(code))


def get_tlsh_comparison(first, second):
    return tlsh.diff(first, second)


def get_imphash(file_object):
    if _is_elf_file(file_object):
        try:
            with suppress_stdout():
                functions = normalize_lief_items(lief.parse(file_object.file_path).imported_functions)
            return md5(','.join(sorted(functions)).encode()).hexdigest()
        except Exception:
            logging.error('Could not compute imphash for {}'.format(file_object.file_path), exc_info=True)
    return None


def _is_elf_file(file_object):
    return file_object.processed_analysis['file_type']['mime'] in ['application/x-executable', 'application/x-object', 'application/x-sharedlib']


def normalize_lief_items(functions):
    if functions and not isinstance(functions[0], str):
        return [str(function) for function in functions]
    return list(functions)

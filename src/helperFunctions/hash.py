import logging
from hashlib import new, md5

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
    diff = ssdeep.compare(first, second)
    return diff


def get_tlsh(code):
    return tlsh.hash(make_bytes(code))


def get_tlsh_comparison(first, second):
    return tlsh.diff(first, second)


def check_similarity_of_sets(pair_of_sets, all_sets):
    for first_item in pair_of_sets[0]:
        for second_item in pair_of_sets[1]:
            if first_item != second_item and {first_item, second_item} not in all_sets:
                return False
    return True


def _is_elf_file(file_object):
    file_type = file_object.processed_analysis['file_type']['mime']
    return file_type in ['application/x-executable', 'application/x-object', 'application/x-sharedlib']


def get_imphash(file_object):
    imphash = None
    if _is_elf_file(file_object):
        try:
            with suppress_stdout():
                elf = lief.parse(file_object.file_path)
            imphash = md5(
                ','.join(sorted(elf.imported_functions)).encode()).hexdigest()
        except Exception as e:
            logging.error('Could not compute imphash for ELF {}: {} {}'.format(
                file_object.file_path, type(e), e))
    return imphash

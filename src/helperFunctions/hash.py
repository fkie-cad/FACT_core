import re
import logging
from hashlib import new, md5

from helperFunctions.dataConversion import make_bytes
from helperFunctions.process import complete_shutdown

try:
    import ssdeep
except ImportError:
    complete_shutdown("Could not load ssdeep module. Install it via: BUILD_LIB=1 pip3 install ssdeep")


try:
    import lief
except ImportError:
    complete_shutdown("Could not load lief module. Install it via: BUILD_LIB=1 pip3 install lief")


def get_hash(hash_function, binary):
    binary = make_bytes(binary)
    raw_hash = new(hash_function)
    raw_hash.update(binary)
    string_hash = raw_hash.hexdigest()
    return string_hash


def get_sha256(code):
    return get_hash("sha256", code)


def get_md5(code):
    return get_hash("md5", code)


def get_ssdeep(code):
    binary = make_bytes(code)
    raw_hash = ssdeep.Hash()
    raw_hash.update(binary)
    return raw_hash.digest()

def get_ssdeep_comparison(first, second):
    diff = ssdeep.compare(first, second)
    return diff


def check_similarity_of_sets(pair_of_sets, all_sets):
    for first_item in pair_of_sets[0]:
        for second_item in pair_of_sets[1]:
            if first_item != second_item and {first_item, second_item} not in all_sets:
                return False
    return True


def _is_elf_file(file_object):
    file_type = file_object.processed_analysis['file_type']['full'].lower()
    return re.search(r'elf', file_type) is not None

def get_imphash(file_object):
    imphash = None
    if _is_elf_file(file_object):
        try:
            elf = lief.parse(file_object.file_path)
            imphash = md5(','.join(elf.imported_functions).encode()).hexdigest()
        except Exception as e:
            logging.error('Could not compute imphash for ELF {}: {}'.format(file_object.file_path, str(e)))
    return imphash

if __name__ == '__main__':
    pass

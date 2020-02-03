import logging
from hashlib import md5, new
from typing import Dict, List, Set

import lief
import ssdeep
import tlsh

from helperFunctions.dataConversion import make_bytes, remove_subsets_from_list_of_sets
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


def generate_similarity_sets(list_of_pairs: List[Set[str]]):
    similarity_sets = find_transitive_combinations(generate_similarity_dict(list_of_pairs))
    remove_subsets_from_list_of_sets(similarity_sets)
    return similarity_sets


def generate_similarity_dict(list_of_pairs: List[Set[str]]) -> Dict[str, Set[str]]:
    '''
    :param list_of_pairs: list of pairs of similar files
    :return: dictionary with key file and value dictionary of all similar files
    '''
    similarity_dict = {}
    for set_ in list_of_pairs:
        for element in set_:
            similarity_dict.setdefault(element, set()).update(set_)
    return similarity_dict


def find_transitive_combinations(similarity_dict: Dict[str, Set[str]]) -> List[Set[str]]:
    similarity_sets = []
    for key in similarity_dict:
        referenced_sets = [similarity_dict[other_key] for other_key in similarity_dict[key] if key != other_key]
        intersection = similarity_dict[key].intersection(*referenced_sets)
        if intersection not in similarity_sets:
            similarity_sets.append(intersection)
    return similarity_sets


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

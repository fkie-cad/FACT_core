import sys
from collections import namedtuple
from itertools import chain, combinations
from pathlib import Path
from re import match
from typing import Generator, Match, Optional
from warnings import warn

from pyxdameraulevenshtein import damerau_levenshtein_distance as distance

from analysis.PluginBase import AnalysisBasePlugin

try:
    from ..internal.meta import DB, DB_NAME, get_meta, unbinding
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from meta import DB, DB_NAME, get_meta, unbinding


QUERIES = get_meta()
MAX_TERM_SPREAD = 3  # a range in which the product term is allowed to come after the vendor term for it not to be a false positive
MAX_LEVENSHTEIN_DISTANCE = 3
PRODUCT = namedtuple('Product', 'vendor_name product_name version_number')


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    lookup vulnerabilities from CVE feeds using ID from CPE dictionary
    '''
    NAME = 'cve_lookup'
    DESCRIPTION = 'lookup CVE vulnerabilities'
    MIME_BLACKLIST = ['audio', 'filesystem', 'image', 'video']
    DEPENDENCIES = ['software_components']
    VERSION = '0.0.1'
    SOFTWARE_SPECS = None

    def __init__(self, plugin_administrator, config=None, recursive=True, offline_testing=False):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__, offline_testing=offline_testing)

    def process_object(self, file_object):
        cves = dict()
        for component in file_object.processed_analysis['software_components']['summary']:
            product, version = self._split_component(component)
            if product and version:
                cves[component] = lookup_vulnerabilities_in_database(product_name=product, requested_version=version)

        cves['summary'] = list(set(chain(*cves.values())))
        file_object.processed_analysis[self.NAME] = cves

        return file_object

    @staticmethod
    def _split_component(component: str) -> list:
        component_parts = component.split()
        return component_parts if len(component_parts) == 2 else [''.join(component_parts[:-2]), component_parts[-1]]


def generate_search_terms(product_name: str) -> list:
    terms = product_name.split(' ')
    product_terms = ['_'.join(terms[i:j]).lower() for i, j in combinations(range(len(terms) + 1), 2)]
    return [term for term in product_terms if len(term) > 1 and not term.isdigit()]


def match_cpe(db: DB, product_search_terms: list) -> Generator[namedtuple, None, None]:
    for vendor, product, version in db.select_query(QUERIES['sqlite_queries']['cpe_lookup']):
        for product_term in product_search_terms:
            if terms_match(product_term, product):
                yield PRODUCT(vendor, product, version)
                break


def is_valid_dotted_version(version: str) -> Optional[Match[str]]:
    return match(r'^[a-zA-Z0-9]+(\\\.[a-zA-Z0-9]+)+$', version)


def get_version_index(version: str, index: int) -> str:
    return version.split('\\.')[index]


def compare_version_index(first_version: str, second_version: str, index: int) -> int:
    try:
        return abs(int(get_version_index(first_version, index)) - int(get_version_index(second_version, index)))
    except ValueError:
        return 100


def has_index(string: str, index: int) -> bool:
    return index <= len(string.split('\\.')) - 1


def sort_dotted_versions(cpe_matches: list, version: str) -> list:
    for index, version_digit in enumerate(version.split('\\.')):
        temp = [product for product in cpe_matches if has_index(product.version_number, index) and get_version_index(product.version_number, index) == version_digit]
        if temp:
            cpe_matches = temp
        else:
            break

    cpe_matches.sort(
        key=lambda p: (compare_version_index(p.version_number, version, 0), compare_version_index(p.version_number, version, 1))
    )

    return cpe_matches


def sort_cpe_matches(cpe_matches: list, version: str) -> namedtuple:
    if version.isdigit():
        cpe_matches = [product for product in cpe_matches if product.version_number.isdigit()]
        cpe_matches.sort(key=lambda p: abs(int(p.version_number) - int(version)))
    elif is_valid_dotted_version(version):
        cpe_matches = sort_dotted_versions([product for product in cpe_matches if is_valid_dotted_version(product.version_number)], version)
    else:
        warn('Warning: Version returned from CPE match has invalid type. Returned CPE might not contain relevant version number')

    return cpe_matches[0]


def search_cve(db: DB, product: namedtuple) -> Generator[str, None, None]:
    for cve_id, vendor, product_name, version in db.select_query(QUERIES['sqlite_queries']['cve_lookup']):
        if terms_match(product.vendor_name, vendor) and terms_match(product.product_name, product_name) \
                and (product.version_number.startswith(get_version_index(version, 0)) or version == 'ANY' or version == 'NA'):
            yield cve_id


def terms_match(requested_term: str, source_term: str) -> bool:
    return distance(requested_term, source_term) < MAX_LEVENSHTEIN_DISTANCE


def word_is_in_wordlist(wordlist: list, words: list) -> bool:
    for index in range(min(MAX_TERM_SPREAD, len(wordlist) + 1 - len(words))):
        next_term = index + 1
        if terms_match(wordlist[index], words[0]):
            return remaining_words_present(wordlist[next_term:], words[next_term:])

    return False


def remaining_words_present(wordlist: list, words: list) -> bool:
    for index, term in enumerate(words):
        if not terms_match(term, wordlist[index]):
            return False
    return True


def search_cve_summary(db: DB, product: namedtuple) -> Generator[str, None, None]:
    for cve_id, summary in db.select_query(QUERIES['sqlite_queries']['summary_lookup']):
        if product_is_in_wordlist(product, summary.split(' ')):
            yield cve_id


def product_is_in_wordlist(product: namedtuple, wordlist: list) -> bool:
    vendor = product.vendor_name.split('_')[0]
    product_name = product.product_name.split('_')

    for index, word in enumerate(wordlist):
        word = word.lower()
        next_word = index + 1

        if terms_match(vendor, word) and \
                wordlist_longer_than_sequence(wordlist[next_word:], product_name) and \
                word_is_in_wordlist(wordlist[next_word:], product_name):
            return True

    return False


def wordlist_longer_than_sequence(wordlist: list, sequence: list) -> bool:
    return len(wordlist) >= len(sequence)


def lookup_vulnerabilities_in_database(product_name: str, requested_version: str) -> list:

    with DB(str(Path(__file__).parent.parent / 'internal' / DB_NAME)) as db:
        product_terms, version = unbinding(generate_search_terms(product_name)), unbinding([requested_version])

        matched_product = sort_cpe_matches(list(match_cpe(db, product_terms)), version)

        cve_candidates = list(set(search_cve(db, matched_product)))
        cve_candidates.extend(list(set(search_cve_summary(db, matched_product))))

    return cve_candidates

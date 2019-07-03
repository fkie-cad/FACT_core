from collections import namedtuple
from itertools import combinations
from pathlib import Path
from typing import Generator, Type, Optional, Match
from re import match
from warnings import warn

from pyxdameraulevenshtein import damerau_levenshtein_distance as distance

from analysis.PluginBase import AnalysisBasePlugin

from ..internal.meta import unbinding, get_meta, DB

QUERIES = get_meta()
MAX_TERM_SPREAD = 3  # a range in which the product term is allowed to come after the vendor term for it not to be a false positive
MAX_LEVENSHTEIN_DISTANCE = 3


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

    def __init__(self, plugin_administrator, config=None, recursive=True):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        cves = dict()
        for component in file_object.processed_analysis['software_components']['summary']:
            product, version = self._split_component(component)
            cves[component] = lookup_vulnerabilities_in_database(product_name=product, requested_version=version)

        cves['summary'] = list({cve for cve in [matches for matches in cves.values()]})
        file_object.processed_analysis[self.NAME] = cves

        return file_object

    @staticmethod
    def _split_component(component: str) -> list:
        component_parts = component.split('')
        return component_parts if len(component_parts) == 2 else [''.join(component_parts[:-2]), component_parts[-1]]


def generate_search_terms(product_name: str) -> list:
    product_terms = [term for term in product_name.split() if len(term) > 1 and not term.isdigit()]
    return ['_'.join(product_terms[i:j]).lower() for i, j in combinations(range(len(product_terms) + 1), 2)]


def match_cpe(db: Type[DB], product_search_terms: list) -> Generator[tuple, None, None]:
    for vendor, product, version in db.select_query(QUERIES['sqlite_queries']['cpe_lookup']):
        for product_term in product_search_terms:
            if terms_match(product_term, product):
                yield (vendor, product, version)
                break


def is_valid_dotted_version(version: str) -> Optional[Match[str]]:
    return match(r'^[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)+$', version)


def hasindex(string: str, index: int) -> bool:
    return index <= len(string.split('.'))-1


def sort_dotted_versions(cpe_matches: list, version: str) -> list:
    dotted_version_matches = [cpe for cpe in cpe_matches if '.' in cpe[2]]
    for index, version_digit in enumerate(version.split('.')):
        temp = [cpe for cpe in dotted_version_matches if hasindex(cpe[2], index) and cpe[2].split('.')[index] == version_digit]
        if temp:
            dotted_version_matches = temp
        else:
            break

    dotted_version_matches.sort(key=lambda v: distance(v[2], version))

    return dotted_version_matches


def sort_cpe_matches(cpe_matches: list, version: str) -> tuple:
    if version.isdigit():
        cpe_matches.sort(key=lambda v: abs(int(v[2])-int(version)))
    elif is_valid_dotted_version(version):
        cpe_matches = sort_dotted_versions(cpe_matches, version)
    else:
        warn('Warning: Version returned from CPE match has invalid type. Returned CPE might not contain relevant version number')

    return cpe_matches[0]


def search_cve(db: Type[DB], product: namedtuple) -> Generator[str, None, None]:
    for cve_id, vendor, product_name, version in db.select_query(QUERIES['sqlite_queries']['cve_lookup']):
        if terms_match(product.vendor_name, vendor) and terms_match(product.product_name, product_name) \
                and (product.version_number.startswith(version) or version == 'ANY' or version == 'NA'):
            yield cve_id


def terms_match(requested_term: str, source_term: str) -> bool:
    return distance(requested_term, source_term) < MAX_LEVENSHTEIN_DISTANCE


def word_is_in_wordlist(wordlist: list, words: list) -> bool:
    for index in range(min(MAX_TERM_SPREAD, len(wordlist))):
        next_term = index + 1

        if terms_match(words[0], wordlist[index]) and wordlist_longer_than_word(wordlist[next_term:], words[next_term:]):
            return True if len(words) == 1 else remaining_words_present(words, wordlist[next_term:])

    return False


def remaining_words_present(product_name: list, wordlist: list) -> bool:
    for index, term in enumerate(product_name):
        if not terms_match(term, wordlist[index]):
            return False
    return True


def search_cve_summary(db: Type[DB], product: namedtuple) -> Generator[str, None, None]:
    for cve_id, summary in db.select_query(QUERIES['sqlite_queries']['summary_lookup']):
        if product_is_in_wordlist(product, summary.split(' ')):
            yield cve_id


def product_is_in_wordlist(product: namedtuple, wordlist: list) -> bool:
    vendor = product.vendor_name.split('_')[0]
    product_name = product.product_name.split('_')

    for index, word in enumerate(wordlist):
        word = word.lower()
        next_word = index + 2

        if terms_match(vendor, word) and \
                wordlist_longer_than_word(wordlist[next_word:], product_name) and \
                word_is_in_wordlist(wordlist[next_word:], product_name):
            return True

    return False


def wordlist_longer_than_word(wordlist: list, product_name: list) -> bool:
    return len(wordlist) >= len(product_name)


def lookup_vulnerabilities_in_database(product_name: str, requested_version: str) -> list:
    Product = namedtuple('Product', 'vendor_name product_name version_number')

    with DB(str(Path(__file__).parent.parent) + '/internal/cpe_cve.db') as db:
        product_terms, version = unbinding(generate_search_terms(product_name)), unbinding([requested_version])

        vendor, product, version = sort_cpe_matches(list(match_cpe(db, product_terms)), version)
        matched_product = Product(vendor, product, version)

        cve_candidates = list(set(list(search_cve(db, matched_product))))
        cve_candidates.extend(list(search_cve_summary(db, matched_product)))

    return cve_candidates

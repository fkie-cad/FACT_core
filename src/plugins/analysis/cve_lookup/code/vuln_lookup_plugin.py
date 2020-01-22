import logging
import operator
import sys
from collections import namedtuple
from distutils.version import LooseVersion, StrictVersion
from itertools import combinations
from pathlib import Path
from re import match
from typing import Callable, List, Optional, Tuple
from warnings import warn

from packaging.version import LegacyVersion, parse
from pyxdameraulevenshtein import damerau_levenshtein_distance as distance  # pylint: disable=no-name-in-module

from analysis.PluginBase import AnalysisBasePlugin

try:
    from ..internal.database_interface import DatabaseInterface, QUERIES
    from ..internal.helper_functions import unbind, unescape
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from database_interface import DatabaseInterface, QUERIES
    from helper_functions import unbind, unescape

MAX_TERM_SPREAD = 3  # a range in which the product term is allowed to come after the vendor term for it not to be a false positive
MAX_LEVENSHTEIN_DISTANCE = 0
PRODUCT = namedtuple('Product', ['vendor_name', 'product_name', 'version_number'])
MATCH_FOUND = 2


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    lookup vulnerabilities from CVE feeds using ID from CPE dictionary
    '''
    NAME = 'cve_lookup'
    DESCRIPTION = 'lookup CVE vulnerabilities'
    MIME_BLACKLIST = ['audio', 'filesystem', 'image', 'video']
    DEPENDENCIES = ['software_components']
    VERSION = '0.0.2'

    def __init__(self, plugin_administrator, config=None, recursive=True, offline_testing=False):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__, offline_testing=offline_testing)

    def process_object(self, file_object):
        cves = {'cve_results': {}}
        for component in file_object.processed_analysis['software_components']['summary']:
            product, version = self._split_component(component)
            if product and version:
                vulnerabilities = lookup_vulnerabilities_in_database(product_name=product, requested_version=version)
                if vulnerabilities:
                    cves['cve_results'][component] = vulnerabilities

        cves['summary'] = list({cve_id for software in cves['cve_results'] for cve_id in cves['cve_results'][software]})
        file_object.processed_analysis[self.NAME] = cves

        return file_object

    @staticmethod
    def _split_component(component: str) -> Tuple[str, str]:
        component_parts = component.split()
        if len(component_parts) == 1:
            return component_parts[0], 'ANY'
        return ''.join(component_parts[:-1]), component_parts[-1]


def lookup_vulnerabilities_in_database(product_name: str, requested_version: str) -> Optional[dict]:
    with DatabaseInterface() as db:
        product_terms, version = unbind(generate_search_terms(product_name)), unbind([requested_version])[0]

        matched_cpe = match_cpe(db, product_terms)
        if len(matched_cpe) == 0:
            logging.debug('No CPEs were found for product {}'.format(product_name))
            return None
        try:
            matched_product = find_matching_cpe_product(matched_cpe, version)
        except IndexError:
            return None
        cve_candidates = search_cve(db, matched_product)
        cve_candidates.update(search_cve_summary(db, matched_product))

        return cve_candidates


def generate_search_terms(product_name: str) -> List[str]:
    terms = product_name.split(' ')
    product_terms = ['_'.join(terms[i:j]).lower() for i, j in combinations(range(len(terms) + 1), 2)]
    return [term for term in product_terms if len(term) > 1 and not term.isdigit()]


def find_matching_cpe_product(cpe_matches: List[PRODUCT], requested_version: str) -> PRODUCT:
    if requested_version.isdigit() or is_valid_dotted_version(requested_version):
        version_numbers = get_version_numbers(cpe_matches)
        if requested_version in version_numbers:
            return find_cpe_product_with_version(cpe_matches, requested_version)
        version_numbers.append(requested_version)
        version_numbers.sort(key=lambda v: LegacyVersion(parse(v)))
        closest_match = get_closest_matches(target_values=version_numbers, search_word=requested_version)[0]
        return find_cpe_product_with_version(cpe_matches, closest_match)
    if requested_version == 'ANY':
        return find_cpe_product_with_version(cpe_matches, 'ANY')
    warn('Warning: Version returned from CPE match has invalid type. Returned CPE might not contain relevant version number')
    return cpe_matches[0]


def is_valid_dotted_version(version: str) -> bool:
    return bool(match(r'^[a-zA-Z0-9\-]+(\\\.[a-zA-Z0-9\-]+)+$', version))


def get_version_numbers(target_values: List[PRODUCT]) -> List[str]:
    return [t.version_number for t in target_values]


def find_cpe_product_with_version(cpe_matches, requested_version):
    return [product for product in cpe_matches if product.version_number == requested_version][0]


def get_closest_matches(target_values: list, search_word: str) -> list:
    search_word_index = target_values.index(search_word)
    if 0 < search_word_index < len(target_values) - 1:
        return [target_values[search_word_index - 1], target_values[search_word_index + 1]]
    if search_word_index == 0:
        return [target_values[search_word_index + 1]]
    return [target_values[search_word_index - 1]]


def build_version_string(version: str, version_start_including: str, version_start_excluding: str,
                         version_end_including: str, version_end_excluding: str) -> str:
    if not any([version_start_including, version_start_excluding, version_end_including, version_end_excluding]):
        return version
    result = 'version'
    if version_start_including:
        result = '{} ≤ {}'.format(version_start_including, result)
    elif version_start_excluding:
        result = '{} < {}'.format(version_start_excluding, result)
    if version_end_including:
        result = '{} ≤ {}'.format(result, version_end_including)
    elif version_end_excluding:
        result = '{} < {}'.format(result, version_end_excluding)
    return result


def search_cve(db: DatabaseInterface, product: PRODUCT) -> dict:
    return {
        cve_id: {
            'score2': cvss_v2_score, 'score3': cvss_v3_score,
            'cpe_version': build_version_string(unescape(version), version_start_including, version_start_excluding,
                                                version_end_including, version_end_excluding)
        }
        for cve_id, vendor, product_name, version, cvss_v2_score, cvss_v3_score, version_start_including,
        version_start_excluding, version_end_including, version_end_excluding in db.select_query(QUERIES['cve_lookup'])
        if terms_match(product.vendor_name, vendor)
        and terms_match(product.product_name, product_name)
        and versions_match(unescape(product.version_number), unescape(version), version_start_including,
                           version_start_excluding, version_end_including, version_end_excluding)
    }


def versions_match(cpe_version: str, cve_version: str, version_start_including: str, version_start_excluding: str,
                   version_end_including: str, version_end_excluding: str) -> bool:
    for version_boundary, operator_ in [
            (version_start_including, operator.le), (version_start_excluding, operator.lt),
            (version_end_including, operator.ge), (version_end_excluding, operator.gt)
    ]:
        if version_boundary and not compare_version(version_boundary, cpe_version, operator_):
            return False
    if cve_version not in ['ANY', 'N/A'] and not compare_version(cve_version, cpe_version, operator.eq):
        return False
    return True


def compare_version(version1: str, version2: str, comp_operator: Callable) -> bool:
    try:
        if not comp_operator(StrictVersion(version1), StrictVersion(version2)):
            return False
    except ValueError:
        try:
            if not comp_operator(LooseVersion(version1), LooseVersion(version2)):
                return False
        except TypeError:
            return False
    return True


def get_version_index(version: str, index: int) -> str:
    return version.split('\\.')[index]


def search_cve_summary(db: DatabaseInterface, product: namedtuple) -> dict:
    return {
        cve_id: {'score2': cvss_v2_score, 'score3': cvss_v3_score}
        for cve_id, summary, cvss_v2_score, cvss_v3_score in db.select_query(QUERIES['summary_lookup'])
        if product_is_in_wordlist(product, summary.split(' '))
    }


def product_is_in_wordlist(product: PRODUCT, wordlist: List[str]) -> bool:
    vendor = product.vendor_name.split('_')[0]
    product_name = product.product_name.split('_')

    for index, word in enumerate(wordlist):
        word = word.lower()
        if terms_match(vendor, word) and word_is_in_wordlist(wordlist[index + 1:], product_name):
            return True

    return False


def word_is_in_wordlist(wordlist: List[str], words: List[str]) -> bool:
    if len(wordlist) < len(words):
        return False
    for index in range(min(MAX_TERM_SPREAD, len(wordlist) + 1 - len(words))):
        if terms_match(wordlist[index], words[0]):
            return remaining_words_present(wordlist[index + 1:], words[1:])
    return False


def remaining_words_present(wordlist: List[str], words: List[str]) -> bool:
    for index, term in enumerate(words):
        if not terms_match(term, wordlist[index]):
            return False
    return True


def match_cpe(db: DatabaseInterface, product_search_terms: list) -> List[PRODUCT]:
    return list({
        PRODUCT(vendor, product, version)
        for vendor, product, version in db.select_query(QUERIES['cpe_lookup'])
        for product_term in product_search_terms
        if terms_match(product_term, product)
    })


def terms_match(requested_term: str, source_term: str) -> bool:
    if MAX_LEVENSHTEIN_DISTANCE > 0:
        return distance(requested_term, source_term) < MAX_LEVENSHTEIN_DISTANCE
    return requested_term == source_term

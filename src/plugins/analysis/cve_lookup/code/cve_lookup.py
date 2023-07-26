from __future__ import annotations

import logging
import operator
import re
import sys
from itertools import combinations
from pathlib import Path
from typing import NamedTuple, TYPE_CHECKING

from packaging.version import InvalidVersion, Version
from packaging.version import parse as parse_version
from pyxdameraulevenshtein import damerau_levenshtein_distance as distance  # pylint: disable=no-name-in-module

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.tag import TagColor
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

if TYPE_CHECKING:
    from objects.file import FileObject
    from collections.abc import Callable
    from collections import namedtuple

try:
    from ..internal.database_interface import QUERIES, DatabaseInterface
    from ..internal.helper_functions import replace_characters_and_wildcards, unescape
    from ..internal.busybox_cve_filter import filter_busybox_cves
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from database_interface import QUERIES, DatabaseInterface
    from helper_functions import replace_characters_and_wildcards, unescape
    from busybox_cve_filter import filter_busybox_cves

MAX_TERM_SPREAD = (
    3  # a range in which the product term is allowed to come after the vendor term for it not to be a false positive
)
MAX_LEVENSHTEIN_DISTANCE = 0
DOTTED_VERSION_REGEX = re.compile(r'^[a-zA-Z0-9\-]+(\\\.[a-zA-Z0-9\-]+)+$')
VALID_VERSION_REGEX = re.compile(r'v?(\d+!)?\d+(\.\d+)*([.-]?(a(lpha)?|b(eta)?|c|dev|post|pre(view)?|r|rc)?\d+)?')


class Product(NamedTuple):
    vendor_name: str
    product_name: str
    version_number: str


class CveDbEntry(NamedTuple):
    cve_id: str
    vendor: str
    product_name: str
    version: str
    cvss_v2_score: str
    cvss_v3_score: str
    version_start_including: str
    version_start_excluding: str
    version_end_including: str
    version_end_excluding: str


class AnalysisPlugin(AnalysisBasePlugin):
    """
    lookup vulnerabilities from CVE feeds using ID from CPE dictionary
    """

    NAME = 'cve_lookup'
    DESCRIPTION = 'lookup CVE vulnerabilities'
    MIME_BLACKLIST = MIME_BLACKLIST_NON_EXECUTABLE
    DEPENDENCIES = ['software_components']
    VERSION = '0.0.5'
    FILE = __file__

    def process_object(self, file_object):
        cves = {'cve_results': {}}
        for component in file_object.processed_analysis['software_components']['summary']:
            product, version = self._split_component(component)
            if product and version:
                vulnerabilities = look_up_vulnerabilities(product_name=product, requested_version=version)
                if vulnerabilities:
                    if 'busybox' in generate_search_terms(product):
                        vulnerabilities = filter_busybox_cves(file_object, vulnerabilities, version)
                    cves['cve_results'][component] = vulnerabilities

        cves['summary'] = self._create_summary(cves['cve_results'])
        file_object.processed_analysis[self.NAME] = cves
        self.add_tags(cves['cve_results'], file_object)
        return file_object

    def _create_summary(self, cve_results: dict[str, dict[str, dict[str, str]]]) -> list[str]:
        return list(
            {
                software if not self._software_has_critical_cve(entry) else f'{software} (CRITICAL)'
                for software, entry in cve_results.items()
            }
        )

    def _software_has_critical_cve(self, cve_dict: dict[str, dict[str, str]]) -> bool:
        return any(self._entry_has_critical_rating(entry) for entry in cve_dict.values())

    def add_tags(self, cve_results: dict[str, dict[str, dict[str, str]]], file_object: FileObject):
        # results structure: {'component': {'cve_id': {'score2': '6.4', 'score3': 'N/A'}}}
        for component in cve_results:
            for cve_id in cve_results[component]:
                entry = cve_results[component][cve_id]
                if self._entry_has_critical_rating(entry):
                    self.add_analysis_tag(file_object, 'CVE', 'critical CVE', TagColor.RED, True)
                    return

    @staticmethod
    def _entry_has_critical_rating(entry):
        return any(entry[key] != 'N/A' and float(entry[key]) >= 9.0 for key in ['score2', 'score3'])

    @staticmethod
    def _split_component(component: str) -> tuple[str, str]:
        component_parts = component.split()
        if len(component_parts) == 1:
            return component_parts[0], 'ANY'
        return ' '.join(component_parts[:-1]), component_parts[-1]


def look_up_vulnerabilities(product_name: str, requested_version: str) -> dict | None:
    with DatabaseInterface() as db:
        product_terms, version = (
            replace_characters_and_wildcards(generate_search_terms(product_name)),
            replace_characters_and_wildcards([requested_version])[0],
        )

        matched_cpe = match_cpe(db, product_terms)
        if len(matched_cpe) == 0:
            logging.debug(f'No CPEs were found for product {product_name}')
            return None
        try:
            matched_product = find_matching_cpe_product(matched_cpe, version)
        except IndexError:
            return None

        cve_candidates = search_cve(db, matched_product)
        cve_candidates.update(search_cve_summary(db, matched_product))
    return cve_candidates


def generate_search_terms(product_name: str) -> list[str]:
    terms = product_name.split(' ')
    product_terms = ['_'.join(terms[i:j]).lower() for i, j in combinations(range(len(terms) + 1), 2)]
    return [term for term in product_terms if len(term) > 1 and not term.isdigit()]


def find_matching_cpe_product(cpe_matches: list[Product], requested_version: str) -> Product:
    if requested_version.isdigit() or is_valid_dotted_version(requested_version):
        version_numbers = [t.version_number for t in cpe_matches if t.version_number not in ['N/A', 'ANY']]
        if requested_version in version_numbers:
            return find_cpe_product_with_version(cpe_matches, requested_version)
        version_numbers.append(requested_version)
        version_numbers.sort(key=lambda v: coerce_version(unescape(v)))
        next_closest_version = find_next_closest_version(version_numbers, requested_version)
        return find_cpe_product_with_version(cpe_matches, next_closest_version)
    if requested_version == 'ANY':
        return find_cpe_product_with_version(cpe_matches, 'ANY')
    logging.warning(
        'Version returned from CPE match has invalid type. Returned CPE might not contain relevant version number'
    )
    return cpe_matches[0]


def is_valid_dotted_version(version: str) -> bool:
    return bool(DOTTED_VERSION_REGEX.match(version))


def find_cpe_product_with_version(cpe_matches, requested_version):
    return [product for product in cpe_matches if product.version_number == requested_version][0]


def find_next_closest_version(sorted_version_list: list[str], requested_version: str) -> str:
    search_word_index = sorted_version_list.index(requested_version)
    if search_word_index == 0:
        return sorted_version_list[search_word_index + 1]
    return sorted_version_list[search_word_index - 1]


def build_version_string(cve_entry: CveDbEntry) -> str:
    if not any(
        [
            cve_entry.version_start_including,
            cve_entry.version_start_excluding,
            cve_entry.version_end_including,
            cve_entry.version_end_excluding,
        ]
    ):
        return unescape(cve_entry.version)
    result = 'version'
    if cve_entry.version_start_including:
        result = f'{cve_entry.version_start_including} ≤ {result}'
    elif cve_entry.version_start_excluding:
        result = f'{cve_entry.version_start_excluding} < {result}'
    if cve_entry.version_end_including:
        result = f'{result} ≤ {cve_entry.version_end_including}'
    elif cve_entry.version_end_excluding:
        result = f'{result} < {cve_entry.version_end_excluding}'
    return result


def search_cve(db: DatabaseInterface, product: Product) -> dict:
    result = {}
    for query_result in db.fetch_multiple(QUERIES['cve_lookup']):
        cve_entry = CveDbEntry(*query_result)
        if _product_matches_cve(product, cve_entry):
            result[cve_entry.cve_id] = {
                'score2': cve_entry.cvss_v2_score,
                'score3': cve_entry.cvss_v3_score,
                'cpe_version': build_version_string(cve_entry),
            }
    return result


def _product_matches_cve(product: Product, cve_entry: CveDbEntry) -> bool:
    return (
        terms_match(product.vendor_name, cve_entry.vendor)
        and terms_match(product.product_name, cve_entry.product_name)
        and versions_match(unescape(product.version_number), cve_entry)
    )


def versions_match(cpe_version: str, cve_entry: CveDbEntry) -> bool:
    for version_boundary, operator_ in [
        (cve_entry.version_start_including, operator.le),
        (cve_entry.version_start_excluding, operator.lt),
        (cve_entry.version_end_including, operator.ge),
        (cve_entry.version_end_excluding, operator.gt),
    ]:
        if version_boundary and not compare_version(version_boundary, cpe_version, operator_):
            return False
    cve_version = unescape(cve_entry.version)
    if cve_version not in ['ANY', 'N/A'] and not compare_version(cve_version, cpe_version, operator.eq):
        return False
    return True


def coerce_version(version: str) -> Version:
    """
    The version may not be PEP 440 compliant -> try to convert it to something that we can use for comparison
    """
    try:
        return parse_version(version)
    except InvalidVersion:
        # try to convert other conventions (e.g. debian policy) to PEP 440
        fixed_version = version.lower().replace('~', '-').replace(':', '!', 1).replace('_', '-')
    try:
        return parse_version(fixed_version)
    except InvalidVersion:
        match = VALID_VERSION_REGEX.match(fixed_version)
        if match:
            valid_version = match.group()
            rest = re.sub(r'[^\w.-]', '', fixed_version[len(valid_version) :]).lstrip('._-')
            return parse_version(f'{valid_version}+{rest}')
        # try to throw away revisions and other stuff at the end as a final measure
        return parse_version(re.split(r'[^v.\d]', fixed_version)[0])


def compare_version(version1: str, version2: str, comp_operator: Callable) -> bool:
    try:
        return comp_operator(coerce_version(version1), coerce_version(version2))
    except InvalidVersion as error:
        logging.debug(f'[cve_lookup]: Error while parsing software version: {error}')
        return False


def search_cve_summary(db: DatabaseInterface, product: namedtuple) -> dict:
    return {
        cve_id: {'score2': cvss_v2_score, 'score3': cvss_v3_score}
        for cve_id, summary, cvss_v2_score, cvss_v3_score in db.fetch_multiple(QUERIES['summary_lookup'])
        if product_is_mentioned_in_summary(product, summary)
    }


def product_is_mentioned_in_summary(product: Product, summary: str) -> bool:
    word_list = summary.split(' ')
    vendor = product.vendor_name.split('_')[0]
    name_components = product.product_name.split('_')

    for index, word in enumerate(word_list):
        if terms_match(vendor, word.lower()) and word_sequence_is_in_word_list(word_list[index + 1 :], name_components):
            return True

    return False


def word_sequence_is_in_word_list(word_list: list[str], word_sequence: list[str]) -> bool:
    if len(word_list) < len(word_sequence):
        return False
    for index in range(min(MAX_TERM_SPREAD, len(word_list) + 1 - len(word_sequence))):
        if terms_match(word_list[index], word_sequence[0]):
            return remaining_words_present(word_list[index + 1 :], word_sequence[1:])
    return False


def remaining_words_present(word_list: list[str], words: list[str]) -> bool:
    return all(terms_match(word1, word2) for word1, word2 in zip(word_list[:len(words)], words))


def match_cpe(db: DatabaseInterface, product_search_terms: list) -> list[Product]:
    return list(
        {
            Product(vendor, product, version)
            for vendor, product, version in db.fetch_multiple(QUERIES['cpe_lookup'])
            for product_term in product_search_terms
            if terms_match(product_term, product)
        }
    )


def terms_match(requested_term: str, source_term: str) -> bool:
    if MAX_LEVENSHTEIN_DISTANCE > 0:
        return distance(requested_term, source_term) < MAX_LEVENSHTEIN_DISTANCE
    return requested_term == source_term

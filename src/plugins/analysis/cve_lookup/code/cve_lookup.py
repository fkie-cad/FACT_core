from __future__ import annotations

import re
import sys
import logging
import operator
from pathlib import Path
from itertools import combinations
from collections.abc import Callable
from packaging.version import parse as parse_version
from packaging.version import InvalidVersion, Version

from objects.file import FileObject
from helperFunctions.tag import TagColor
from analysis.PluginBase import AnalysisBasePlugin
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE


try:
    from ..internal.db_interface import DbInterface
    from ..internal.db_connection import DbConnection
    from ..internal.schema import Association, Cpe
    from ..internal.helper_functions import replace_characters_and_wildcards
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from db_interface import DbInterface
    from db_connection import DbConnection
    from schema import Cpe
    from helper_functions import replace_characters_and_wildcards

VALID_VERSION_REGEX = re.compile(r'v?(\d+!)?\d+(\.\d+)*([.-]?(a(lpha)?|b(eta)?|c|dev|post|pre(view)?|r|rc)?\d+)?')
DB_PATH = str(Path(__file__).parent / '../internal/cve_cpe.db')


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    lookup vulnerabilities from CVE feeds using ID from CPE dictionary
    '''

    NAME = 'cve_lookup'
    DESCRIPTION = 'lookup CVE vulnerabilities'
    MIME_BLACKLIST = MIME_BLACKLIST_NON_EXECUTABLE
    DEPENDENCIES = ['software_components']
    VERSION = '0.0.6'
    FILE = __file__

    def process_object(self, file_object: FileObject) -> FileObject:
        '''
        Process the given file object and look up vulnerabilities for each software component.
        '''
        cves = {'cve_results': {}}
        for component in file_object.processed_analysis['software_components']['summary']:
            product, version = self._split_component(component)
            if product and version:
                vulnerabilities = look_up_vulnerabilities(product_name=product, requested_version=version)
                if vulnerabilities:
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
        '''
        Check if any entry in the given dictionary of CVEs has a critical rating.
        '''
        return any(self._entry_has_critical_rating(entry) for entry in cve_dict.values())

    def add_tags(self, cve_results: dict[str, dict[str, dict[str, str]]], file_object: FileObject):
        '''
        Adds analysis tags to a file object based on the critical CVE results.

        Results structure: {'component': {'cve_id': {'score2': '6.4', 'score3': 'N/A'}}}
        '''
        for component in cve_results:
            for cve_id in cve_results[component]:
                entry = cve_results[component][cve_id]
                if self._entry_has_critical_rating(entry):
                    self.add_analysis_tag(file_object, 'CVE', 'critical CVE', TagColor.RED, True)
                    return

    @staticmethod
    def _entry_has_critical_rating(entry: dict[str, str]) -> bool:
        '''
        Check if the given entry has a critical rating.
        '''
        return any(entry[key] != 'N/A' and float(entry[key]) >= 9.0 for key in ['score2', 'score3'])

    @staticmethod
    def _split_component(component: str) -> tuple[str, str]:
        '''
        Splits a component string into two parts and returns them as a tuple.
        '''
        component_parts = component.split()
        if len(component_parts) == 1:
            return component_parts[0], 'ANY'
        return ' '.join(component_parts[:-1]), component_parts[-1]


def look_up_vulnerabilities(product_name: str, requested_version: str) -> dict:
    '''
    Look up vulnerabilities for a given product and requested version.
    '''
    vulnerabilities = {}
    connection = DbConnection(f'sqlite:///{DB_PATH}')
    db = DbInterface(connection)
    product_terms, version = (
        replace_characters_and_wildcards(generate_search_terms(product_name)),
        replace_characters_and_wildcards([requested_version])[0],
    )
    cpe_matches = db.cpe_matches(product_terms)
    if len(cpe_matches) == 0:
        logging.debug(f'No CPEs were found for product {product_name}')
    else:
        association_matches = find_matching_associations(db, cpe_matches, version)
        for association in association_matches:
            cve = db.cve_lookup(association.cve_id)
            vulnerabilities[cve.cve_id] = {
                'score2': cve.cvss_v2_score,
                'score3': cve.cvss_v3_score,
                'cpe_version': build_version_string(db.cpe_lookup(association.cpe_id), association),
            }
    return vulnerabilities


def generate_search_terms(product_name: str) -> list[str]:
    '''
    Generate a list of search terms that can be used to search for the product.
    '''
    terms = product_name.split(' ')
    product_terms = ['_'.join(terms[i:j]).lower() for i, j in combinations(range(len(terms) + 1), 2)]
    return [term for term in product_terms if len(term) > 1 and not term.isdigit()]


def find_matching_associations(db: DbInterface, cpe_matches: list[Cpe], requested_version: str) -> list[Association]:
    '''
    Find matching associations based on the provided CPE matches and requested version.
    '''
    association_matches = []
    if requested_version in ['ANY', 'N/A']:
        return association_matches
    for cpe in cpe_matches:
        associations = db.associations_lookup(cpe.cpe_id)
        if cpe.version == requested_version:
            association_matches.extend(associations)
        else:
            association_matches.extend(version_in_boundaries(associations, requested_version))
    return association_matches


def version_in_boundaries(associations: list[Association], requested_version: str) -> list[Association]:
    '''
    Find and return the CVE and CPE associations where the requested version is within the version boundaries.
    '''
    association_matches = []
    if requested_version == 'ANY, N/A':
        return association_matches
    for association in associations:
        if not any(
            [
                association.version_start_including,
                association.version_start_excluding,
                association.version_end_including,
                association.version_end_excluding,
            ]
        ):
            continue
        if is_version_in_boundaries(association, requested_version):
            association_matches.append(association)
    return association_matches


def is_version_in_boundaries(association: Association, requested_version: str) -> bool:
    '''
    Check if the requested version is within the boundaries of the given CVE and CPE association.
    '''
    for version_boundary, comp_operator in [
        (association.version_start_including, operator.le),
        (association.version_start_excluding, operator.lt),
        (association.version_end_including, operator.ge),
        (association.version_end_excluding, operator.gt),
    ]:
        if version_boundary and not compare_version(version_boundary, requested_version, comp_operator):
            return False
    return True


def compare_version(version1: str, version2: str, comp_operator: Callable) -> bool:
    '''
    Compare two software versions using the specified comparison operator.
    '''
    try:
        return comp_operator(coerce_version(version1), coerce_version(version2))
    except InvalidVersion as error:
        logging.debug(f'Error while parsing software version: {error}')
    return False


def coerce_version(version: str) -> Version:
    '''
    The version may not be PEP 440 compliant -> try to convert it to something that we can use for comparison
    '''
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


def build_version_string(cpe: Cpe, association: Association) -> str:
    '''
    Build a version string based on the cpe cve association boundaries.
    '''
    if not any(
        [
            association.version_start_including,
            association.version_start_excluding,
            association.version_end_including,
            association.version_end_excluding,
        ]
    ):
        return cpe.version
    result = 'version'
    if association.version_start_including:
        result = f'{association.version_start_including} ≤ {result}'
    elif association.version_start_excluding:
        result = f'{association.version_start_excluding} < {result}'
    if association.version_end_including:
        result = f'{result} ≤ {association.version_end_including}'
    elif association.version_end_excluding:
        result = f'{result} < {association.version_end_excluding}'
    return result

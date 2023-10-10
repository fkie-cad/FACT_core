from __future__ import annotations

import re
import logging
import operator
from itertools import combinations
from packaging.version import parse as parse_version
from packaging.version import InvalidVersion, Version

from .busybox_cve_filter import filter_busybox_cves
from .database.db_interface import DbInterface
from .helper_functions import replace_wildcards
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .database.db_connection import DbConnection
    from .database.schema import Association, Cpe
    from collections.abc import Callable
    from objects.file import FileObject

VALID_VERSION_REGEX = re.compile(r'v?(\d+!)?\d+(\.\d+)*([.-]?(a(lpha)?|b(eta)?|c|dev|post|pre(view)?|r|rc)?\d+)?')


class Lookup:
    def __init__(self, file_object: FileObject, connection: DbConnection):
        self.file_object = file_object
        self.db_interface = DbInterface(connection)

    def lookup_vulnerabilities(
        self,
        product_name: str,
        requested_version: str,
    ) -> dict:
        """
        Look up vulnerabilities for a given product and requested version.
        """
        vulnerabilities = {}
        product_terms, version = (
            self._generate_search_terms(product_name),
            replace_wildcards([requested_version])[0],
        )
        cpe_matches = self.db_interface.match_cpes(product_terms)
        if len(cpe_matches) == 0:
            logging.debug(f'No CPEs were found for product {product_name}')
        else:
            association_matches = self._find_matching_associations(cpe_matches, version)
            cve_ids = [association.cve_id for association in association_matches]
            cves = self.db_interface.get_cves(cve_ids)
            if 'busybox' in product_terms:
                cves = filter_busybox_cves(self.file_object, cves)
            for association in association_matches:
                cve = cves.get(association.cve_id)
                if cve:
                    cpe = cpe_matches.get(association.cpe_id)
                    if cpe:
                        vulnerabilities[cve.cve_id] = {
                            'score2': cve.cvss_v2_score,
                            'score3': cve.cvss_v3_score,
                            'cpe_version': self._build_version_string(association, cpe),
                        }

        return vulnerabilities

    @staticmethod
    def _generate_search_terms(product_name: str) -> list[str]:
        """
        Generate a list of search terms that can be used to search for the product.
        """
        terms = product_name.split(' ')
        product_terms = ['_'.join(terms[i:j]).lower() for i, j in combinations(range(len(terms) + 1), 2)]
        return [term for term in product_terms if len(term) > 1 and not term.isdigit()]

    def _find_matching_associations(self, cpe_matches: dict[str, Cpe], requested_version: str) -> list[Association]:
        """
        Find matching associations based on the provided CPE matches and requested version.
        """
        association_matches: list[Association] = []
        if requested_version in {'ANY', 'N/A'}:
            return association_matches

        cpe_ids = [cpe.cpe_id for cpe in cpe_matches.values()]
        associations_dict = self.db_interface.get_associations(cpe_ids)

        for cpe in cpe_matches.values():
            associations = associations_dict.get(cpe.cpe_id, [])
            if cpe.version == requested_version:
                association_matches += associations
            else:
                association_matches += self._version_in_boundaries(associations, requested_version)
        return association_matches

    def _version_in_boundaries(self, associations: list[Association], requested_version: str) -> list[Association]:
        """
        Find and return the CVE and CPE associations where the requested version is within the version boundaries.
        """
        association_matches: list[Association] = []
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
            if self._is_version_in_boundaries(association, requested_version):
                association_matches.append(association)
        return association_matches

    def _is_version_in_boundaries(self, association: Association, requested_version: str) -> bool:
        """
        Check if the requested version is within the boundaries of the given CVE and CPE association.
        """
        for version_boundary, comp_operator in [
            (association.version_start_including, operator.le),
            (association.version_start_excluding, operator.lt),
            (association.version_end_including, operator.ge),
            (association.version_end_excluding, operator.gt),
        ]:
            if version_boundary and not self._compare_version(version_boundary, requested_version, comp_operator):
                return False
        return True

    def _compare_version(self, version1: str, version2: str, comp_operator: Callable) -> bool:
        """
        Compare two software versions using the specified comparison operator.
        """
        try:
            return comp_operator(self._coerce_version(version1), self._coerce_version(version2))
        except InvalidVersion as error:
            logging.debug(f'Error while parsing software version: {error}')
        return False

    @staticmethod
    def _coerce_version(version: str) -> Version:
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

    def _build_version_string(self, association: Association, cpe: Cpe) -> str:
        """
        Build a version string based on the cpe cve association boundaries.
        """
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

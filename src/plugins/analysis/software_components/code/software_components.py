from __future__ import annotations

import os
import re

from common_helper_files import get_dir_of_file

from analysis.YaraPluginBase import YaraBasePlugin
from config import cfg
from helperFunctions.data_conversion import make_unicode_string
from helperFunctions.tag import TagColor
from objects.file import FileObject
from plugins.analysis.software_components.bin import OS_LIST
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

from ..internal.resolve_version_format_string import extract_data_from_ghidra
from itertools import combinations
import dataclasses
from plugins.analysis.cve_lookup.internal.helper_functions import unescape
import plugins.analysis.cve_lookup.internal.database_interface as cve_database_interface

import packaging
from packaging.version import InvalidVersion, Version
import logging

SIGNATURE_DIR = os.path.join(get_dir_of_file(__file__), '../signatures')
DOTTED_VERSION_REGEX = re.compile(r'^[a-zA-Z0-9\-]+(\\\.[a-zA-Z0-9\-]+)+$')
VALID_VERSION_REGEX = re.compile(r'v?(\d+!)?\d+(\.\d+)*([.-]?(a(lpha)?|b(eta)?|c|dev|post|pre(view)?|r|rc)?\d+)?')


@dataclasses.dataclass(frozen=True)
class PartialCPE:
    """A dataclass that contains some fileds of a CPE."""
    vendor: str
    product: str
    version: str


class AnalysisPlugin(YaraBasePlugin):
    '''
    This plugin identifies software components

    Credits:
    OS Tagging functionality created by Roman Konertz during Firmware Bootcamp WT17/18 at University of Bonn
    Maintained by Fraunhofer FKIE
    '''

    NAME = 'software_components'
    DESCRIPTION = 'identify software components'
    MIME_BLACKLIST = MIME_BLACKLIST_NON_EXECUTABLE
    VERSION = '0.4.2'
    FILE = __file__

    def process_object(self, file_object):
        file_object = super().process_object(file_object)
        analysis = file_object.processed_analysis[self.NAME]
        # No yara matches found (The only key is "summary" or "failed")
        if len(analysis) <= 1:
            return file_object

        for item, component_dict in analysis.items():
            if item == "summary":
                continue
            metadata = component_dict["meta"]
            strings = [string for _, _, string in component_dict["strings"]]
            versions = _versions_from_metadata(file_object, metadata, strings)
            # TODO: component_dict['meta'] contains the 'meta' section of yara rules.
            # Manually adding things later does not make sense.
            analysis[item]["meta"]["version"] = list(versions)
            # TODO Why are dataclasses not JSONSerializable?
            analysis[item]["cpes"] = [dataclasses.asdict(cpe) for cpe in _cpes_from_metadata(file_object, metadata, strings)]

        analysis['summary'] = _summarize(analysis)
        self.add_os_key(file_object)

        return file_object

    def add_os_key(self, file_object):
        for entry in file_object.processed_analysis[self.NAME]['summary']:
            for os_ in OS_LIST:
                if entry.find(os_) != -1:
                    if self._entry_has_no_trailing_version(entry, os_):
                        self.add_analysis_tag(file_object, 'OS', entry, TagColor.GREEN, True)
                    else:
                        self.add_analysis_tag(file_object, 'OS', os_, TagColor.GREEN, False)
                        self.add_analysis_tag(file_object, 'OS Version', entry, TagColor.GREEN, True)

    @staticmethod
    def _entry_has_no_trailing_version(entry, os_string):
        return os_string.strip() == entry.strip()


def _strip_zeroes(version_string: str) -> str:
    return '.'.join(element.lstrip('0') or '0' for element in version_string.split('.'))


def _product_search_terms(software_name: str) -> list[str]:
    """Returns a list of terms that are matched against the 'product' of a CPE."""
    terms = software_name.split(' ')
    product_terms = ['_'.join(terms[i:j]).lower() for i, j in combinations(range(len(terms) + 1), 2)]
    return [term for term in product_terms if len(term) > 1 and not term.isdigit()]


def _cpes_from_metadata(file_object: FileObject, metadata: dict, strings: list[str]) -> list[PartialCPE]:
    """Returns a list CPEs from yara result metadata.
    Fields of metadata are matched against a table of all CPEs.
    """
    cpes: list[PartialCPE] = []
    # TODO this could be imporved. If the yara rules (which are handcrafted anyways) contained the actual product as
    # defined in the CPE for the software we could throw out _product_search_terms
    software_name = metadata["software_name"]
    # TODO replace_characters_and_wildcards

    cve_db = cve_database_interface.DatabaseInterface()
    # First get all CPEs for the given product
    product_cpes = list({
        PartialCPE(cpe_vendor, cpe_product, cpe_version)
        for cpe_vendor, cpe_product, cpe_version in cve_db.fetch_multiple(cve_database_interface.QUERIES['cpe_lookup'])
        for product_term in _product_search_terms(software_name)
        if product_term == software_name
    })

    # Now filter out all CPEs whose version does not match any of the versions we need
    versions = _versions_from_metadata(file_object, metadata, strings)
    # TODO reimplement and audit the functions used here
    for version in versions:
        try:
            cpe = find_matching_cpe_product(product_cpes, version)
            cpes.append(cpe)
        except IndexError:
            pass

    print(f"{cpes=}")
    return cpes


def _versions_from_metadata(file_object: FileObject, metadata: dict, strings: list[str]) -> set[str]:
    """Returns a list of possible version strings using the yara result metadata.
    """
    versions = set()

    version_regex = metadata.get("version_regex", r'\\d+.\\d+(.\\d+)?(\\w)?')
    versions = versions | _versions_from_regex(version_regex, strings)

    if metadata.get("format_string", False):
        versions = versions | _versions_from_format_strings(file_object.binary, strings)

    return versions


def _versions_from_regex(regex_spec: str, strings: list[str]) -> set[str]:
    versions = set()
    # The regex is not a valid python regex.
    regex_spec = regex_spec.replace("\\\\", "\\")
    regex = re.compile(regex_spec)

    for string in strings:
        regex_match = regex.search(make_unicode_string(string))
        if regex_match is None:
            continue
        versions.add(_strip_zeroes(regex_match.group(0)))

    return versions


def _versions_from_format_strings(binary: bytes, strings: list[str]) -> set[str]:
    # binary is the binary of the file to be analyzed
    versions = set()

    key_strings = [string for string in strings if '%s' in string]
    if key_strings:
        versions.update(
            extract_data_from_ghidra(binary, key_strings, cfg.data_storage.docker_mount_base_dir)
        )

    return versions


def _summarize(processed_analysis: dict):
    summary = set()
    for item, component_dict in processed_analysis.items():
        if item == "summary":
            continue

        software = component_dict['meta']['software_name']
        # If we did not detect any versions just omit it.
        versions = component_dict['meta']['version'] or ['']
        for version in versions:
            summary.add(f'{software} {version}')
    return sorted(summary)


class SoftwareVersion:
    DOTTET_REGEX = re.compile(r'^[a-zA-Z0-9\-]+(\\\.[a-zA-Z0-9\-]+)+$')

    def __init__(self, version: str):
        self._version = version

    def is_dotted(self):
        return bool(SoftwareVersion.DOTTET_REGEX.match(self._version))


def find_matching_cpe_product(cpe_matches: list[PartialCPE], requested_version: str) -> PartialCPE:
    if requested_version.isdigit() or is_valid_dotted_version(requested_version):
        version_numbers = [cpe.version for cpe in cpe_matches if cpe.version not in ['N/A', 'ANY']]
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


def find_cpe_product_with_version(cpe_matches, requested_version) -> PartialCPE:
    return [cpe for cpe in cpe_matches if cpe.version == requested_version][0]


def find_next_closest_version(sorted_version_list: list[str], requested_version: str) -> str:
    search_word_index = sorted_version_list.index(requested_version)
    if search_word_index == 0:
        return sorted_version_list[search_word_index + 1]
    return sorted_version_list[search_word_index - 1]


def coerce_version(version: str) -> Version:
    '''
    The version may not be PEP 440 compliant -> try to convert it to something that we can use for comparison
    '''
    try:
        return packaging.version.parse(version)
    except InvalidVersion:
        # try to convert other conventions (e.g. debian policy) to PEP 440
        fixed_version = version.lower().replace('~', '-').replace(':', '!', 1).replace('_', '-')
    try:
        return packaging.version.parse(fixed_version)
    except InvalidVersion:
        match = VALID_VERSION_REGEX.match(fixed_version)
        if match:
            valid_version = match.group()
            rest = re.sub(r'[^\w.-]', '', fixed_version[len(valid_version) :]).lstrip('._-')
            return packaging.version.parse(f'{valid_version}+{rest}')
        # try to throw away revisions and other stuff at the end as a final measure
        return packaging.version.parse(re.split(r'[^v.\d]', fixed_version)[0])

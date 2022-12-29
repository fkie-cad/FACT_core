from __future__ import annotations

import logging
import sys
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from analysis.YaraPluginBase import YaraBasePlugin
from helperFunctions.tag import TagColor

try:
    from ..internal.key_parser import read_asn1_key, read_pkcs_cert, read_ssl_cert
except ImportError:
    sys.path.append(str(Path(__file__).parent.parent / 'internal'))
    from key_parser import read_asn1_key, read_pkcs_cert, read_ssl_cert


class Match(NamedTuple):
    offset: int
    label: str
    matched_string: str


class AnalysisPlugin(YaraBasePlugin):
    '''
    Searches for known Crypto material (e.g., public and private keys)
    '''

    NAME = 'crypto_material'
    DESCRIPTION = 'detects crypto material like SSH keys and SSL certificates'
    VERSION = '0.5.2'
    MIME_BLACKLIST = ['filesystem']
    FILE = __file__

    STARTEND = [
        'PgpPublicKeyBlock',
        'PgpPrivateKeyBlock',
        'PgpPublicKeyBlock_GnuPG',
        'genericPublicKey',
        'SshRsaPrivateKeyBlock',
        'SshEncryptedRsaPrivateKeyBlock',
        'SSLPrivateKey',
    ]
    STARTONLY = ['SshRsaPublicKeyBlock']
    PKCS8 = 'Pkcs8PrivateKey'
    PKCS12 = 'Pkcs12Certificate'
    SSLCERT = 'SSLCertificate'

    def process_object(self, file_object):
        file_object = super().process_object(file_object)
        yara_results = file_object.processed_analysis[self.NAME]
        analysis_result = self.convert_yara_result(yara_results, file_object.binary)
        analysis_result['summary'] = list(analysis_result)

        file_object.processed_analysis[self.NAME] = analysis_result
        self._add_private_key_tag(file_object, analysis_result)
        return file_object

    def convert_yara_result(self, yara_results, binary):
        analysis_result = {}
        for matching_rule in yara_results.get('summary', []):
            matches = [Match(*t) for t in yara_results[matching_rule]['strings']]
            matches.sort(key=lambda m: m.offset)
            parsing_function = self._get_parsing_function(matching_rule)
            if not parsing_function:
                continue
            crypto_items = parsing_function(matches=matches, binary=binary)
            if crypto_items:
                analysis_result[matching_rule] = {'material': crypto_items, 'count': len(crypto_items)}
        return analysis_result

    def _get_parsing_function(self, match: str) -> Callable | None:
        if match in self.STARTEND:
            return self.extract_labeled_keys
        if match in self.STARTONLY:
            return self.extract_start_only_key
        if match == self.PKCS8:
            return self.get_pkcs8_key
        if match == self.PKCS12:
            return self.get_pkcs12_cert
        if match == self.SSLCERT:
            return self.get_ssl_cert
        logging.warning(f'Unknown crypto rule match: {match}')
        return None

    def extract_labeled_keys(self, matches: list[Match], binary, min_key_len=128) -> list[str]:
        return [
            binary[start:end].decode(encoding='utf_8', errors='replace')
            for start, end in self.get_offset_pairs(matches)
            if end - start > min_key_len
        ]

    @staticmethod
    def extract_start_only_key(matches: list[Match], **_) -> list[str]:
        return [match.matched_string for match in matches if match.label == '$start_string']

    @staticmethod
    def get_pkcs8_key(matches: list[Match], binary=None) -> list[str]:
        keys = []
        for match in matches:
            key = read_asn1_key(binary=binary, offset=match.offset)
            if key is not None:
                keys.append(key)
        return keys

    @staticmethod
    def get_pkcs12_cert(matches: list[Match], binary=None) -> list[str]:
        keys = []
        for match in matches:
            text_cert = read_pkcs_cert(binary=binary, offset=match.offset)
            if text_cert is not None:
                keys.append(text_cert)
        return keys

    def get_ssl_cert(self, matches: list[Match], binary=None) -> list[str]:
        contents = []
        for pair in self.get_offset_pairs(matches):
            start_index, end_index = pair
            text_cert = read_ssl_cert(binary=binary, start=start_index, end=end_index)
            if text_cert is not None:
                contents.append(text_cert)
        return contents

    @staticmethod
    def get_offset_pairs(matches: list[Match]):
        pairs = []
        for index in range(len(matches) - 1):
            if _is_consecutive_key_block(matches, index):
                pairs.append((matches[index].offset, _calculate_end_index(matches[index + 1])))
            elif _is_consecutive_pgp_block(matches, index):
                pairs.append((matches[index].offset, _calculate_end_index(matches[index + 2])))
            elif _is_consecutive_encrypted_key(matches, index):
                pairs.append((matches[index].offset, _calculate_end_index(matches[index + 3])))
        return pairs

    def _add_private_key_tag(self, file_object, result):
        if any('private' in key.lower() for key in result):
            self.add_analysis_tag(
                file_object=file_object,
                tag_name='private_key_inside',
                value='Private Key Found',
                color=TagColor.ORANGE,
                propagate=True,
            )


def _is_consecutive_key_block(matches: list[Match], index: int) -> bool:
    return matches[index].label == '$start_string' and matches[index + 1].label == '$end_string'


def _is_consecutive_pgp_block(matches: list[Match], index: int) -> bool:
    return (
        matches[index].label == '$start_string'
        and matches[index + 1].label == '$gnupg_version_string'
        and len(matches) > index + 2
        and matches[index + 2].label == '$end_string'
    )


def _is_consecutive_encrypted_key(matches: list[Match], index: int) -> bool:
    return (
        len(matches) > index + 3
        and matches[index].label == '$start_string'
        and matches[index + 1].label == '$proc_type'
        and matches[index + 2].label == '$dek_info'
        and matches[index + 3].label == '$end_string'
    )


def _calculate_end_index(match: Match) -> int:
    return match.offset + len(match.matched_string)

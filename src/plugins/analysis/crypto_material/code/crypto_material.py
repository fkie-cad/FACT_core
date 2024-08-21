from __future__ import annotations

import logging
from typing import TYPE_CHECKING, List, NamedTuple

from pydantic import BaseModel, Field

from analysis.plugin import AnalysisPluginV0, Tag, addons, compat
from analysis.plugin.compat import AnalysisBasePluginAdapterMixin
from helperFunctions.hash import get_md5
from helperFunctions.tag import TagColor
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED

from ..internal.key_parser import read_asn1_key, read_pkcs_cert, read_ssl_cert

if TYPE_CHECKING:
    import io
    from collections.abc import Callable

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


class Match(NamedTuple):
    offset: int
    label: str
    matched_string: str


def _read_from_file(file_handle: io.FileIO, start: int, end: int) -> bytes:
    file_handle.seek(start)
    return file_handle.read(end - start)


class CryptoMaterialMatch(BaseModel):
    rule: str = Field(description='The YARA rule that matched this crypto material')
    material: List[str] = Field(description='An array with the contents of the matched keys/certificates')
    count: int = Field(description='The number of matched keys/certificates')
    hashes: List[str] = Field(description='The MD5 hashes of the keys/certificates (in the same order as `material`)')


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    """
    Searches for known Crypto material (e.g., public and private keys)
    """

    class Schema(BaseModel):
        matches: List[CryptoMaterialMatch] = Field(description='A list of matched crypto material')

    def __init__(self):
        metadata = self.MetaData(
            name='crypto_material',
            description='detects crypto material like SSH keys and SSL certificates',
            version='1.0.0',
            mime_blacklist=['filesystem', *MIME_BLACKLIST_COMPRESSED],
            Schema=self.Schema,
        )
        super().__init__(metadata=metadata)
        self._yara = addons.Yara(plugin=self)

    def analyze(self, file_handle: io.FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path, analyses
        raw_yara_results = [compat.yara_match_to_dict(m) for m in self._yara.match(file_handle)]
        return self.Schema(matches=self.convert_yara_result(raw_yara_results, file_handle))

    def convert_yara_result(self, yara_results: list[dict], file_handle: io.FileIO) -> list[CryptoMaterialMatch]:
        analysis_result = []
        for matching_rule in yara_results:
            matches = [Match(*t) for t in matching_rule['strings']]
            matches.sort(key=lambda m: m.offset)
            parsing_function = self._get_parsing_function(matching_rule['rule'])
            if not parsing_function:
                continue
            crypto_items: list[str] = parsing_function(matches=matches, file_handle=file_handle)
            hashes = [get_md5(item) for item in crypto_items]
            if crypto_items:
                analysis_result.append(
                    CryptoMaterialMatch(
                        rule=matching_rule['rule'],
                        material=crypto_items,
                        count=len(crypto_items),
                        hashes=hashes,
                    )
                )
        return analysis_result

    def _get_parsing_function(self, match: str) -> Callable | None:
        if match in STARTEND:
            return self.extract_labeled_keys
        if match in STARTONLY:
            return self.extract_start_only_key
        if match == PKCS8:
            return self.get_pkcs8_key
        if match == PKCS12:
            return self.get_pkcs12_cert
        if match == SSLCERT:
            return self.get_ssl_cert
        logging.warning(f'Unknown crypto rule match: {match}')
        return None

    def extract_labeled_keys(self, matches: list[Match], file_handle: io.FileIO, min_key_len=128) -> list[str]:
        return [
            _read_from_file(file_handle, start, end).decode(encoding='utf_8', errors='replace')
            for start, end in self.get_offset_pairs(matches)
            if end - start > min_key_len
        ]

    @staticmethod
    def extract_start_only_key(matches: list[Match], **_) -> list[str]:
        return [match.matched_string for match in matches if match.label == '$start_string']

    @staticmethod
    def get_pkcs8_key(matches: list[Match], file_handle: io.FileIO) -> list[str]:
        keys = []
        for match in matches:
            key = read_asn1_key(file_handle=file_handle, offset=match.offset)
            if key is not None:
                keys.append(key)
        return keys

    @staticmethod
    def get_pkcs12_cert(matches: list[Match], file_handle: io.FileIO) -> list[str]:
        keys = []
        for match in matches:
            text_cert = read_pkcs_cert(file_handle=file_handle, offset=match.offset)
            if text_cert is not None:
                keys.append(text_cert)
        return keys

    def get_ssl_cert(self, matches: list[Match], file_handle: io.FileIO) -> list[str]:
        contents = []
        for start_index, end_index in self.get_offset_pairs(matches):
            text_cert = read_ssl_cert(file_handle=file_handle, start=start_index, end=end_index)
            if text_cert is not None:
                contents.append(text_cert)
        return contents

    @staticmethod
    def get_offset_pairs(matches: list[Match]) -> list[tuple[int, int]]:
        pairs = []
        for index in range(len(matches) - 1):
            if _is_consecutive_key_block(matches, index):
                pairs.append((matches[index].offset, _calculate_end_index(matches[index + 1])))
            elif _is_consecutive_pgp_block(matches, index):
                pairs.append((matches[index].offset, _calculate_end_index(matches[index + 2])))
            elif _is_consecutive_encrypted_key(matches, index):
                pairs.append((matches[index].offset, _calculate_end_index(matches[index + 3])))
        return pairs

    def summarize(self, result: AnalysisPlugin.Schema) -> list[str]:
        return [match.rule for match in result.matches]

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del result
        if any('private' in item.lower() for item in summary):
            tag = Tag(
                name='private_key_inside',
                value='Private Key Found',
                color=TagColor.ORANGE,
                propagate=True,
            )
            return [tag]
        return []


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

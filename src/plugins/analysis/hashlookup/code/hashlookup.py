from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import requests
from flor import BloomFilter
from pydantic import BaseModel, Field, model_validator
from semver import Version

import config
from analysis.plugin import AnalysisFailedError, AnalysisPluginV0
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED, MIME_BLACKLIST_NON_EXECUTABLE

if TYPE_CHECKING:
    from io import FileIO

    from plugins.analysis.hash.code.hash import AnalysisPlugin as HashPlugin

BLOOM_FILTER_PATH = Path(__file__).parent.parent / 'bin' / 'hashlookup-full.bloom'


class HashLookupError(Exception):
    pass


class ValidatorModel(BaseModel):
    """
    This model validator converts all "-" or ":" chars in keys to "_"
    """

    @model_validator(mode='before')
    @classmethod
    def _normalize_keys(cls, values: dict) -> dict:
        if isinstance(values, dict):
            return {k.replace('-', '_').replace(':', '_'): v for k, v in values.items()}
        return values


class OperatingSystem(BaseModel):
    OpSystemCode: str = Field(description='Operating system ID')
    OpSystemName: str
    OpSystemVersion: str | None = None
    MfgCode: str | None = Field(None, description='vendor or manufacturer ID')


class Product(BaseModel):
    ProductCode: int = Field(description='software product ID')
    ProductName: str
    ApplicationType: str | None = Field(None, description='general use of the software product')
    Language: str | None = Field(None, description='language(s) used in the software product')
    MfgCode: str | None = Field(None, description='vendor or manufacturer ID')
    OpSystemCode: str | None = Field(None, description='operating system version ID')
    ProductVersion: str | None = Field(None, description='version of the software product')


class File(ValidatorModel):
    SHA_1: str = Field(description='SHA-1 hash (hex, uppercase)')
    PackageName: str | None = None
    PackageMaintainer: str | None = None


class HashLookupResult(ValidatorModel):
    # API fields as described in https://www.ietf.org/archive/id/draft-dulaunoy-hashlookup-format-03.html
    # and https://www.nist.gov/system/files/data-formats-of-the-nsrl-reference-data-set-16.pdf
    FileName: str
    FileSize: int = Field(description='Size in bytes')
    MD5: str = Field(description='MD5 hash (hex, uppercase)')
    SHA_1: str = Field(description='SHA-1 hash (hex, uppercase)')
    SHA_256: str = Field(description='SHA-256 hash (hex, uppercase)')

    db: str | None = Field(None, description='Db where the file come from')
    TLSH: str | None = Field(None, description='TLSH fuzzy hash')
    CRC32: str | None = Field(None, description='CRC32 checksum of the file')
    SSDEEP: str | None = Field(None, description='SSDEEP fuzzy hash')
    source: str | None = Field(None, description='Source of the file')
    parents: list[File] | None = Field(None, description='represent the relationships with other hashlookup objects')
    children: list[File] | None = Field(None, description='represent the relationships with other hashlookup objects')
    ProductCode: Product | None = Field(None, description='associated software product')
    SpecialCode: str | None = Field(None, description='Special file signatures (e.g. M: malicious, S: special)')
    OpSystemCode: OperatingSystem | None = Field(None, description='associated Operating system')
    RDS_package_id: str | None = Field(None, description='nist NSRL RDS package ID')
    hashlookup_trust: int | None = None
    insert_timestamp: str | None = None
    SHA_512: str | None = Field(None, description='SHA-512 hash (hex, uppercase)')
    mimetype: str | None = Field(None, description='Guessed mimetype of the file')
    tar_gname: str | None = Field(None, description='Group name used to create the Tar archive')
    tar_uname: str | None = Field(None, description='User name used to create the Tar archive')
    nsrl_sha256: str | None = Field(
        None, description='Specifies if the file SHA-256 comes from the original NSRL SHA-1 to SHA-256 list'
    )
    KnownMalicious: str | None = Field(
        None, description='List of source considering the hashed file as being malicious'
    )


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(ValidatorModel):
        known: bool
        lookup_result: HashLookupResult | None = Field(
            None,
            description=(
                'Result of the hash lookup in the standardized hashlookup format '
                '(see https://www.ietf.org/archive/id/draft-dulaunoy-hashlookup-format-00.html)'
            ),
        )

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='hashlookup',
                    description=(
                        'Query a hash library (by default: circl.lu) to identify known binaries. The default library '
                        'contains file hashes for multiple *nix distributions and the NIST software reference library.'
                    ),
                    dependencies=['file_hashes'],
                    mime_blacklist=[*MIME_BLACKLIST_NON_EXECUTABLE, *MIME_BLACKLIST_COMPRESSED],
                    version=Version(2, 0, 0),
                    Schema=self.Schema,
                )
            )
        )
        self.bloom_filter = self._init_bloom_filter()
        self.url = getattr(config.backend.plugin.get(self.metadata.name, {}), 'server', 'https://hashlookup.circl.lu')

    def _init_bloom_filter(self) -> BloomFilter | None:
        self.local_only = getattr(config.backend.plugin.get(self.metadata.name, {}), 'local_only', False)
        if self.local_only and not BLOOM_FILTER_PATH.is_file():
            raise FileNotFoundError(f'Expected file {BLOOM_FILTER_PATH} not found')

        if BLOOM_FILTER_PATH.is_file():
            bloom_filter = BloomFilter()
            with BLOOM_FILTER_PATH.open('rb') as fp:
                bloom_filter.read(fp)
            logging.debug(f'[{self.metadata.name}]: loaded Bloom filter {BLOOM_FILTER_PATH}')
        else:
            bloom_filter = None
        return bloom_filter

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, HashPlugin.Schema]) -> Schema:
        del file_handle, virtual_file_path
        if 'file_hashes' not in analyses or analyses['file_hashes'].sha1 is None:
            raise AnalysisFailedError('sha1 hash is missing in dependency results')
        sha1_hash = analyses['file_hashes'].sha1.upper()

        if self.bloom_filter is not None:
            if not self.bloom_filter.check(sha1_hash.encode()):
                return self.Schema(known=False)
            if self.local_only:
                return self.Schema(known=True)

        result = self._look_up_hash(sha1_hash)

        if 'FileName' not in result:
            if 'message' in result and 'Non existing' in result['message']:
                # sha256 hash unknown to hashlookup at time of analysis'
                return self.Schema(known=False)
            raise HashLookupError(f'Unknown error connecting to hashlookup API: {result}')
        return self.Schema(known=True, lookup_result=HashLookupResult.model_validate(result))

    def summarize(self, result: Schema) -> list[str]:
        return ['known hash'] if result.known else []

    def _look_up_hash(self, sha1_hash: str) -> dict:
        try:
            url = f'{self.url}/lookup/sha1/{sha1_hash}'
            return requests.get(url, headers={'accept': 'application/json'}).json()  # noqa: S113
        except (requests.ConnectionError, json.JSONDecodeError) as error:
            raise AnalysisFailedError('Failed to connect to hashlookup server') from error

from __future__ import annotations

import json
from typing import TYPE_CHECKING, List, Optional

import requests
from pydantic import BaseModel, Field, model_validator
from semver import Version

from analysis.plugin import AnalysisPluginV0
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED, MIME_BLACKLIST_NON_EXECUTABLE

if TYPE_CHECKING:
    from io import FileIO


class HashLookupError(Exception):
    pass


class ValidatorModel(BaseModel):
    """
    This model validator converts all "-" or ":" chars in keys to "_"
    """

    @model_validator(mode='before')
    @classmethod
    def _normalize_keys(cls, values):
        if isinstance(values, dict):
            return {k.replace('-', '_').replace(':', '_'): v for k, v in values.items()}
        return values


class OperatingSystem(BaseModel):
    OpSystemCode: str = Field(description='Operating system ID')
    OpSystemName: str
    OpSystemVersion: Optional[str] = None
    MfgCode: Optional[str] = Field(None, description='vendor or manufacturer ID')


class Product(BaseModel):
    ProductCode: int = Field(description='software product ID')
    ProductName: str
    ApplicationType: Optional[str] = Field(None, description='general use of the software product')
    Language: Optional[str] = Field(None, description='language(s) used in the software product')
    MfgCode: Optional[str] = Field(None, description='vendor or manufacturer ID')
    OpSystemCode: Optional[str] = Field(None, description='operating system version ID')
    ProductVersion: Optional[str] = Field(None, description='version of the software product')


class File(ValidatorModel):
    SHA_1: str = Field(description='SHA-1 hash (hex, uppercase)')
    PackageName: Optional[str] = None
    PackageMaintainer: Optional[str] = None


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(ValidatorModel):
        # API fields as described in https://www.ietf.org/archive/id/draft-dulaunoy-hashlookup-format-03.html
        # and https://www.nist.gov/system/files/data-formats-of-the-nsrl-reference-data-set-16.pdf
        FileName: str
        FileSize: int = Field(description='Size in bytes')
        MD5: str = Field(None, description='MD5 hash (hex, uppercase)')
        SHA_1: str = Field(None, description='SHA-1 hash (hex, uppercase)')
        SHA_256: str = Field(None, description='SHA-256 hash (hex, uppercase)')

        db: Optional[str] = Field(None, description='Db where the file come from')
        TLSH: Optional[str] = Field(None, description='TLSH fuzzy hash')
        CRC32: Optional[str] = Field(None, description='CRC32 checksum of the file')
        SSDEEP: Optional[str] = Field(None, description='SSDEEP fuzzy hash')
        source: Optional[str] = Field(None, description='Source of the file')
        parents: List[Optional[File]] = Field(
            None, description='represent the relationships with other hashlookup objects'
        )
        children: List[Optional[File]] = Field(
            None, description='represent the relationships with other hashlookup objects'
        )
        ProductCode: Optional[Product] = Field(None, description='associated software product')
        SpecialCode: Optional[str] = Field(None, description='Special file signatures (e.g. M: malicious, S: special)')
        OpSystemCode: Optional[OperatingSystem] = Field(None, description='associated Operating system')
        RDS_package_id: Optional[str] = Field(None, description='nist NSRL RDS package ID')
        hashlookup_trust: Optional[int] = None
        insert_timestamp: Optional[str] = None
        SHA_512: Optional[str] = Field(None, description='SHA-512 hash (hex, uppercase)')
        mimetype: Optional[str] = Field(None, description='Guessed mimetype of the file')
        tar_gname: Optional[str] = Field(None, description='Group name used to create the Tar archive')
        tar_uname: Optional[str] = Field(None, description='User name used to create the Tar archive')
        nsrl_sha256: Optional[str] = Field(
            None, description='Specifies if the file SHA-256 comes from the original NSRL SHA-1 to SHA-256 list'
        )
        KnownMalicious: Optional[str] = Field(
            None, description='List of source considering the hashed file as being malicious'
        )

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='hashlookup',
                    description=(
                        'Querying the circl.lu hash library to identify known binaries. The library contains file '
                        'hashes for multiple *nix distributions and the NIST software reference library.'
                    ),
                    dependencies=['file_hashes'],
                    mime_blacklist=[*MIME_BLACKLIST_NON_EXECUTABLE, *MIME_BLACKLIST_COMPRESSED],
                    version=Version(1, 0, 0),
                    Schema=self.Schema,
                )
            )
        )

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]) -> Schema | None:
        del file_handle, virtual_file_path
        try:
            sha2_hash = analyses['file_hashes'].sha256
        except (KeyError, AttributeError) as error:
            raise HashLookupError('sha256 hash is missing in dependency results') from error

        result = _look_up_hash(sha2_hash.upper())

        if 'FileName' not in result:
            if 'message' in result and result['message'] == 'Non existing SHA-256':
                # sha256 hash unknown to hashlookup at time of analysis'
                return None
            raise HashLookupError('Unknown error connecting to hashlookup API')
        return self.Schema.model_validate(result)

    def summarize(self, result: Schema) -> list[str]:
        return [result.FileName] if result else []


def _look_up_hash(sha2_hash: str) -> dict:
    try:
        url = f'https://hashlookup.circl.lu/lookup/sha256/{sha2_hash}'
        return requests.get(url, headers={'accept': 'application/json'}).json()
    except (requests.ConnectionError, json.JSONDecodeError) as error:
        raise HashLookupError('Failed to connect to circl.lu hashlookup API') from error

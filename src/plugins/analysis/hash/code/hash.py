from __future__ import annotations

import logging
from hashlib import algorithms_guaranteed
from typing import TYPE_CHECKING, Optional

import lief
import ssdeep
import tlsh
from pydantic import BaseModel, Field
from semver import Version

import config
from analysis.plugin import AnalysisPluginV0
from helperFunctions.hash import get_hash, get_md5

if TYPE_CHECKING:
    from io import FileIO

ELF_MIME_TYPES = [
    'application/x-executable',
    'application/x-object',
    'application/x-pie-executable',
    'application/x-sharedlib',
]


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(BaseModel):
        # The supported hashes are the ones from helperFunctions.hash and hashlib (except "shake" which is of
        # little use considering its variable length).
        # If they are not supported on the platform or not selected in the configuration of the plugin, the value will
        # be `None`.
        # Only the md5 and sha256 hashes are guaranteed to be available (since they are required down the line)

        # from hashlib
        md5: str = Field(description="md5 hash of the file's content")
        sha256: str = Field(description="sha256 hash of the file's content")
        sha1: Optional[str] = Field(description="sha1 hash of the file's content", default=None)
        sha224: Optional[str] = Field(description="sha224 hash of the file's content", default=None)
        sha384: Optional[str] = Field(description="sha384 hash of the file's content", default=None)
        sha512: Optional[str] = Field(description="sha512 hash of the file's content", default=None)
        blake2b: Optional[str] = Field(description="blake2b hash of the file's content", default=None)
        blake2s: Optional[str] = Field(description="blake2s hash of the file's content", default=None)
        sha3_224: Optional[str] = Field(description="sha3_224 hash of the file's content", default=None)
        sha3_256: Optional[str] = Field(description="sha3_256 hash of the file's content", default=None)
        sha3_384: Optional[str] = Field(description="sha3_384 hash of the file's content", default=None)
        sha3_512: Optional[str] = Field(description="sha3_512 hash of the file's content", default=None)

        ssdeep: Optional[str] = Field(description="ssdeep hash of the file's content", default=None)
        tlsh: Optional[str] = Field(description="tlsh hash of the file's content", default=None)
        imphash: Optional[str] = Field(
            description='import hash: the MD5 hash of the sorted imported functions (ELF files only)',
            default=None,
        )

    def __init__(self):
        super().__init__(
            metadata=self.MetaData(
                name='file_hashes',
                description='calculate different hash values of the file',
                version=Version(1, 3, 0),
                dependencies=['file_type'],
                Schema=self.Schema,
            ),
        )
        configured_hashes = getattr(config.backend.plugin.get(self.metadata.name, None), 'hashes', [])
        self.hashes_to_create = set(configured_hashes).union({'sha256', 'md5'})

    def analyze(self, file_handle: FileIO, virtual_file_path: str, analyses: dict) -> Schema:
        del virtual_file_path
        result = {}

        file_handle.seek(0)
        file_contents = file_handle.read()
        for hash_ in self.hashes_to_create.intersection(algorithms_guaranteed):
            result[hash_] = get_hash(hash_, file_contents)
        result['ssdeep'] = get_ssdeep(file_contents)
        result['imphash'] = get_imphash(file_handle, analyses.get('file_type'))
        result['tlsh'] = get_tlsh(file_contents)

        return self.Schema(**result)


def get_imphash(file: FileIO, type_analysis: BaseModel | None) -> str | None:
    """
    Generates and returns the md5 hash for the (sorted) imported functions of an ELF file.
    Returns `None` if there are no imports or if an exception occurs.
    """
    if type_analysis is not None and _is_elf_file(type_analysis):
        try:
            if (parsed_elf := lief.ELF.parse(file.name)) is not None and len(parsed_elf.imported_functions) > 0:
                functions = [f.name for f in parsed_elf.imported_functions]
                return get_md5(','.join(sorted(functions)))
        except Exception as error:
            logging.warning(f'Could not compute imphash for {file}: {error}')
    return None


def _is_elf_file(type_analysis: BaseModel) -> bool:
    return type_analysis.mime in ELF_MIME_TYPES


def get_ssdeep(file_contents: bytes) -> str:
    raw_hash = ssdeep.Hash()
    raw_hash.update(file_contents)
    return raw_hash.digest()


def get_tlsh(file_contents: bytes) -> str | None:
    tlsh_hash = tlsh.hash(file_contents)
    return tlsh_hash if tlsh_hash != 'TNULL' else None

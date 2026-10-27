from __future__ import annotations

from itertools import chain
from pathlib import Path
from typing import TYPE_CHECKING

import pydantic
from pydantic import Field
from semver import Version

from analysis.plugin import AnalysisPluginV0, Tag
from helperFunctions.tag import TagColor
from plugins.analysis.users_and_passwords.internal.credentials_finder import (
    CredentialResult,
    HtpasswdCredentialFinder,
    MosquittoCredentialFinder,
    UnixCredentialFinder,
)
from plugins.mime_blacklists import MIME_BLACKLIST_NON_EXECUTABLE

if TYPE_CHECKING:
    from io import FileIO


class AnalysisPlugin(AnalysisPluginV0):
    class Schema(pydantic.BaseModel):
        unix: list[CredentialResult] = Field(description='The list of found UNIX credentials.')
        http: list[CredentialResult] = Field(description='The list of found HTTP basic auth credentials.')
        mosquitto: list[CredentialResult] = Field(description='The list of found Mosquitto MQTT broker credentials.')

    def __init__(self):
        super().__init__(
            metadata=self.MetaData(
                name='users_and_passwords',
                description=(
                    'Searches for user/password entries in standard locations (e.g. /etc/passwd, /etc/shadow, '
                    '/etc/master.passwd) as well as httpd and Mosquitto MQTT broker credential files. Parses them, '
                    'extracts cleartext passwords, and attempts to crack weak password hashes.'
                ),
                tooltip='search for password files and try to crack the passwords',
                version=Version(1, 1, 0),
                Schema=self.Schema,
                mime_blacklist=MIME_BLACKLIST_NON_EXECUTABLE,
            ),
        )

    def analyze(self, file_handle: FileIO, virtual_file_path: dict[str, list[str]], analyses: dict) -> Schema:
        del virtual_file_path, analyses
        file_contents = Path(file_handle.name).read_bytes()
        return self.Schema(
            unix=UnixCredentialFinder.find_credentials(file_contents),
            http=HtpasswdCredentialFinder.find_credentials(file_contents),
            mosquitto=MosquittoCredentialFinder.find_credentials(file_contents),
        )

    def summarize(self, result: Schema) -> list[str]:
        return [f'{entry.username}:{entry.type}' for entry in chain(result.unix, result.http, result.mosquitto)]

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del summary
        return [
            Tag(
                name=f'{entry.username}_{entry.password}',
                value=f'Password: {entry.username}:{entry.password}',
                color=TagColor.RED,
                propagate=True,
            )
            for entry in chain(result.unix, result.http, result.mosquitto)
            if entry.password
        ]

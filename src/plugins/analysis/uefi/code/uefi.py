from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List, Optional, TYPE_CHECKING

from pydantic import BaseModel, Field

from analysis.plugin import AnalysisPluginV0, Tag
from analysis.plugin.compat import AnalysisBasePluginAdapterMixin
from helperFunctions.docker import run_docker_container

from docker.types import Mount

from helperFunctions.tag import TagColor

if TYPE_CHECKING:
    from io import FileIO

DOCKER_IMAGE = 'fact/uefi'


class Variant(BaseModel):
    name: str = Field(description='The name of the vulnerability variant')
    match: bool = Field(description='Whether there was a match for this vulnerability')
    output: str = Field(description='The output of FwHunt')


class Rule(BaseModel):
    name: str = Field(description='The name of the rule')
    category: str = Field(description='The rule category (e.g. vulnerabilities or mitigation failures)')
    author: Optional[str] = Field(None, description='The Author of the rule')
    description: Optional[str] = Field(None, description='The description of the rule/vulnerability')
    url: Optional[str] = Field(None, description='A link with more information for this rule/vulnerability')
    variants: List[Variant] = Field(description='The list of variants with matching information')


class Schema(BaseModel):
    vulnerabilities: List[Rule] = Field(description='A list of UEFI vulnerabilities')


class UefiPluginError(Exception):
    pass


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    def __init__(self):
        super().__init__(
            metadata=AnalysisPluginV0.MetaData(
                name='uefi',
                description='find vulnerabilities in UEFI modules using the tool FwHunt',
                dependencies=['file_type'],
                version='0.1.0',
                Schema=Schema,
                mime_whitelist=['application/x-dosexec', 'firmware/uefi'],
            ),
        )

    def analyze(
        self,
        file_handle: FileIO,
        virtual_file_path: dict[str, list[str]],
        analyses: dict[str, BaseModel],
    ) -> Schema | None:
        del virtual_file_path

        type_analysis = analyses['file_type']
        if _is_no_uefi_module(type_analysis):
            # only EFI modules are analyzed, not regular PE files
            return None

        return self._analyze_uefi_module(file_handle.name, _get_analysis_mode(type_analysis.mime))

    def _analyze_uefi_module(self, path: str, mode: str) -> Schema | None:
        with TemporaryDirectory() as tmp_dir:
            output_file = Path(tmp_dir) / 'output.json'
            output_file.touch()
            run_docker_container(
                DOCKER_IMAGE,
                combine_stderr_stdout=True,
                timeout=self.TIMEOUT,
                mounts=[
                    Mount('/input/file', path, type='bind'),
                    Mount('/output/file', str(output_file), type='bind'),
                ],
                environment={'UEFI_ANALYSIS_MODE': mode},
            )
            try:
                return _convert_json_to_schema(json.loads(output_file.read_text()))
            except json.JSONDecodeError as error:
                raise UefiPluginError('Could not load container output') from error

    def summarize(self, result: Schema) -> list[str]:
        summary = set()
        for rule in result.vulnerabilities:
            for variant in rule.variants:
                if variant.match:
                    summary.add(rule.category)
                    continue
        return sorted(summary)

    def get_tags(self, result: Schema, summary: list[str]) -> list[Tag]:
        del result
        return [
            Tag(
                name=category,
                value='UEFI vulnerability',
                color=TagColor.ORANGE,
                propagate=True,
            )
            for category in summary
        ]


def _convert_json_to_schema(fw_hunt_data: dict[str, dict]) -> Schema:
    """
    The output of the docker container has the following structure:
    {
        <rule_name>: {
            category: ...,
            author: ...,
            description: ...,
            [url: ...,]
            variants: {
                <name>: {
                    output: ...,
                    match: ...
                },
                ...
            },
        },
        ...
    }
    """
    vulnerabilities = [
        Rule(
            name=rule_name,
            category=data['category'],
            author=data['author'],
            description=data['description'],
            url=data.get('url') or None,  # fix for empty strings
            variants=[
                Variant(name=variant_name, **variant_data) for variant_name, variant_data in data['variants'].items()
            ],
        )
        for rule_name, data in fw_hunt_data.items()
    ]
    return Schema(vulnerabilities=vulnerabilities)


def _is_no_uefi_module(type_analysis: BaseModel) -> bool:
    return type_analysis.mime == 'application/x-dosexec' and 'EFI boot service driver' not in type_analysis.full


def _get_analysis_mode(mime: str) -> str:
    return 'firmware' if mime == 'firmware/uefi' else 'module'

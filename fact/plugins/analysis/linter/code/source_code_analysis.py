from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional

import pydantic
from docker.types import Mount
from pydantic import Field

from fact.analysis.plugin import AnalysisPluginV0
from fact.analysis.plugin.compat import AnalysisBasePluginAdapterMixin
from fact.helperFunctions.docker import run_docker_container
from fact.helperFunctions.virtual_file_path import get_paths_for_all_parents

from ..internal import linters

if TYPE_CHECKING:
    import io


# All linter methods must return an array of dicts.
# The elements are dicts and must match the Issue model.
LINTER_IMPLS = {
    'javascript': linters.run_eslint,
    'lua': linters.run_luacheck,
    'python': linters.run_pylint,
    'ruby': linters.run_rubocop,
    'shell': linters.run_shellcheck,
    'php': linters.run_phpstan,
}


class AnalysisPlugin(AnalysisPluginV0, AnalysisBasePluginAdapterMixin):
    class Schema(pydantic.BaseModel):
        class Issue(pydantic.BaseModel):
            """A linting issue."""

            symbol: str = Field(
                description=(
                    "An identifier for the linting type. E.g. 'unused-import' (pylint).\n"
                    'Note that this field is linter specific.'
                ),
            )
            type: Optional[str] = Field(None, description="E.g. 'warning' or 'error'")
            message: str = Field(
                description=(
                    # fmt: off
                    'The human readable description of the issue.\n' 'Note that this field is linter specific.'
                ),
            )
            line: int = Field(description='The line in the file where the issue occurred')
            column: int = Field(description='The column in the file where the issue occurred')

        language: Optional[str] = Field(description='The language. Is set to None when no language is detected.')
        linguist: dict = Field(description='The dict output by `linguist --json`.')
        issues: Optional[List[Issue]] = Field(
            description=(
                # fmt: off
                'A list of issues the linter for ``script_type`` found.\n' 'Is set to None if no linter is available.'
            ),
        )

    def __init__(self):
        super().__init__(
            metadata=AnalysisPluginV0.MetaData(
                name='source_code_analysis',
                description='This plugin implements static code analysis for multiple scripting languages',
                version='0.7.1',
                Schema=AnalysisPlugin.Schema,
                mime_whitelist=['text/'],
            ),
        )

    def summarize(self, result: Schema) -> list:
        summary = []
        if result.language is not None:
            summary.append(result.language)
        if result.issues is not None and len(result.issues) > 0:
            summary.append('has-warnings')

        return summary

    def analyze(self, file_handle: io.FileIO, virtual_file_path: dict[str, list[str]], analyses: dict) -> Schema:
        """
        After only receiving text files thanks to the whitelist, we try to detect the correct scripting language
        and then call a linter if a supported language is detected
        """
        del analyses

        language, linguist_json = None, None
        file_names = [Path(file_handle.name).name, *_get_paths_with_different_suffix(virtual_file_path)]
        for name in file_names:
            linguist_json = run_linguist(file_handle.name, name)
            language = linguist_json.get('language')
            if language is not None:
                break

        if language is None:
            return AnalysisPlugin.Schema(
                linguist=linguist_json,
                language=None,
                issues=None,
            )

        language = language.lower()

        if language not in LINTER_IMPLS:
            return AnalysisPlugin.Schema(
                linguist=linguist_json,
                language=language,
                issues=None,
            )

        issues = LINTER_IMPLS[language](file_handle.name)
        issues = sorted(issues, key=lambda k: k['symbol'])

        return AnalysisPlugin.Schema(
            linguist=linguist_json,
            language=language,
            issues=issues,
        )


def run_linguist(file_path: str, virtual_file_name: str) -> dict:
    container_path = f'/repo/{virtual_file_name}'
    result = run_docker_container(
        'crazymax/linguist',
        combine_stderr_stdout=True,
        timeout=60,
        command=f'--json {container_path}',
        mounts=[
            Mount(container_path, file_path, type='bind'),
        ],
        logging_label='source_code_analysis',
    )
    result.check_returncode()
    output_json = json.loads(result.stdout)

    return output_json[container_path]


def _get_paths_with_different_suffix(virtual_file_path: dict[str, list[str]]) -> list[str]:
    """
    A file can have multiple paths if it appears multiple times in one or more firmwares. Return one path per suffix
    for language detection (linguist also considers the suffix while determining the language).
    """
    suffixes = set()
    result = []
    for vfp in sorted(get_paths_for_all_parents(virtual_file_path)):
        path = Path(vfp)
        if path.suffix not in suffixes:
            suffixes.add(path.suffix)
            result.append(path.name)
    return result

from __future__ import annotations

import itertools
import re
from pathlib import Path
from typing import TYPE_CHECKING, List

from pydantic import BaseModel
from semver import Version

from analysis.plugin import AnalysisPluginV0

if TYPE_CHECKING:
    from io import FileIO


PATH_REGEX = {
    'user_paths': re.compile(rb'/home/[^%\n:) \x00]+'),
    'root_path': re.compile(rb'/root/[^%\n:) \x00]+'),
    'www_path': re.compile(rb'/var/www/[^\n:) \x00]+'),
}

FILES_REGEX = {
    'any_history': re.compile(rb'.+_history'),
}

URL_REGEXES = {
    # Based on [1]
    # [1]: https://gitlab.com/gitlab-com/gl-security/security-operations/redteam/redteam-public/tools/token-hunter/-/blob/ebe511793eb0e1ab884e5255ff68198dc5905987/regexes.json#L80
    'credentials_in_url': re.compile(
        rb'([a-zA-Z]{3,10}://[a-zA-Z0-9]{3,20}:[^/\s:@]{3,20}@[A-Za-z0-9._/:%?&${}=-]{7,100})["\'\s\x00]?'
    )
}

PATH_ARTIFACT_DICT = {
    '.git/config': 'git_config',
    '.svn/entries': 'svn_entries',
    '.conda/environments.txt': 'conda_environment',
    'default.conf': 'possible_code_blocks_config',
    'clion64.exe.vmoptions': 'clion_jvm_options',
    'idea.properties': 'clion_platform_properties',
    '.config/Code/User/settings.json': 'vscode_settings',
    '.cproject': 'eclipse_config',
    '.csproject': 'eclipse_config',
    '.project': 'eclipse_config',
    '.bash_history': 'bash_history',
    '.zsh_history': 'zsh_history',
    '.hws': 'renesas_project_config',
    '.ewd': 'iar_embedded_workbench_config',
    '.ewp': 'iar_embedded_workbench_config',
    '.eww': 'iar_embedded_workbench_config',
    '.ewt': 'iar_embedded_workbench_config',
    '.Uv2': 'keil_uvision_config',
    '.uvproj': 'keil_uvision_config',
    '.uvopt': 'keil_uvision_config',
    '.uvprojx': 'keil_uvision_config',
    '.uvoptx': 'keil_uvision_config',
    '.atsln': 'atmel_studio_config',
    '.cyprj': 'cydesigner_config',
    '.cywrk': 'cydesigner_config',
}

DIRECTORY_DICT = {
    '.git': 'git_repository',
    '.svn': 'svn_repository',
    '.github': 'github_config_directory',
    '.pytest_cache': 'pytest_cache_directory',
    '.conda': 'conda_directory',
    '.config': 'config_directory',
    '.subversion': 'svn_user_settings_directory',
    'subversion': 'svn_settings_directory',
    '.idea': 'jetbrains_config_directory',
}


def _filter_files_from_summary(path: str) -> str:
    """if files are in the path list only return the parent directory for the summary"""
    path_object = Path(path)
    if path_object.suffix:
        return str(path_object.parent)
    return path


class Artifact(BaseModel):
    name: str
    path: str


class AnalysisPlugin(AnalysisPluginV0):
    """
    This Plugin searches for leaked information in a firmware,
        e.g., compilation artifacts, VCS repositories, IDE configs and special paths
    """

    class Schema(BaseModel):
        path_artifacts: List[Artifact]
        url_artifacts: List[Artifact]

    def __init__(self):
        super().__init__(
            metadata=(
                self.MetaData(
                    name='information_leaks',
                    description='Find leaked information like compilation artifacts',
                    dependencies=['file_type'],
                    version=Version(1, 0, 0),
                    mime_whitelist=[
                        'application/x-executable',
                        'application/x-object',
                        'application/x-pie-executable',
                        'application/x-sharedlib',
                        'text/plain',
                    ],
                    Schema=self.Schema,
                )
            )
        )

    def analyze(self, file_handle: FileIO, virtual_file_path: dict, analyses: dict[str, BaseModel]) -> Schema:
        file_content = file_handle.read()
        if analyses['file_type'].mime == 'text/plain':
            path_artifacts = _find_artifacts(virtual_file_path)
        else:
            path_artifacts = _find_regex(file_content, PATH_REGEX)
        url_artifacts = _find_regex(file_content, URL_REGEXES)

        return self.Schema(
            path_artifacts=self._to_artifact_list(path_artifacts),
            url_artifacts=self._to_artifact_list(url_artifacts),
        )

    @staticmethod
    def _to_artifact_list(artifacts: dict[str, list[str]]) -> list[Artifact]:
        return [Artifact(name=artifact, path=path) for artifact, path_list in artifacts.items() for path in path_list]

    def summarize(self, result: Schema) -> list[str]:
        return list({artifact.name for artifact in itertools.chain(result.path_artifacts, result.url_artifacts)})


def _find_artifacts(vfp_dict: dict[str, list[str]]) -> dict[str, list[str]]:
    # FixMe: after removal of duplicate unpacking/analysis, all VFPs will only be found after analysis update
    result = {}
    for path_list in vfp_dict.values():
        for path in path_list:
            result.update(_check_file_path(path))
    return result


def _check_file_path(file_path: str) -> dict[str, list[str]]:
    for search_function in (_check_for_files, _check_for_directories, _find_files):
        if results := search_function(file_path):
            return results
    return {}


def _find_files(file_path: str) -> dict[str, list[str]]:
    return _find_regex(file_path.encode(), FILES_REGEX)


def _check_for_files(file_path: str) -> dict[str, list[str]]:
    results = {}
    for key_path, artifact in PATH_ARTIFACT_DICT.items():
        if file_path.endswith(key_path):
            results.setdefault(artifact, []).append(file_path)
    return results


def _check_for_directories(file_path: str) -> dict[str, list[str]]:
    results = {}
    for key_path, artifact in DIRECTORY_DICT.items():
        file_path_list = file_path.split('/')
        if len(file_path_list) > 1 and file_path_list[-2] == key_path:
            results.setdefault(artifact, []).append(file_path)
    return results


def _find_regex(search_term: bytes, regex_dict: dict[str, re.Pattern]) -> dict[str, list[str]]:
    results = {}
    for label, regex in regex_dict.items():
        result = regex.findall(search_term)
        if result:
            result_list = sorted({e.decode(errors='replace') for e in result})
            results.setdefault(label, []).extend(result_list)
    return results

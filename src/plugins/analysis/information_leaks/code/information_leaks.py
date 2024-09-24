from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any

from analysis.PluginBase import AnalysisBasePlugin

if TYPE_CHECKING:
    from objects.file import FileObject

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


class AnalysisPlugin(AnalysisBasePlugin):
    """
    This Plugin searches for leaked information in a firmware,
        e.g., compilation artifacts, VCS repositories, IDE configs and special paths
    """

    NAME = 'information_leaks'
    DEPENDENCIES = []  # noqa: RUF012
    DESCRIPTION = 'Find leaked information like compilation artifacts'
    MIME_WHITELIST = [  # noqa: RUF012
        'application/x-executable',
        'application/x-object',
        'application/x-sharedlib',
        'text/plain',
    ]
    VERSION = '0.2.0'
    FILE = __file__

    def process_object(self, file_object: FileObject) -> FileObject:
        if file_object.processed_analysis['file_type']['result']['mime'] == 'text/plain':
            result, summary = _find_artifacts(file_object)
        else:
            result, summary = _find_regex(file_object.binary, PATH_REGEX)

        url_result, url_summary = _find_regex(file_object.binary, URL_REGEXES)
        result.update(url_result)
        summary.extend(url_summary)

        file_object.processed_analysis[self.NAME] = result
        file_object.processed_analysis[self.NAME]['summary'] = summary
        return file_object


def _find_artifacts(file_object: FileObject) -> tuple[dict[str, Any], list[str]]:
    # FixMe: after removal of duplicate unpacking/analysis, all VFPs will only be found after analysis update
    result = {}
    for virtual_path_list in file_object.virtual_file_path.values():
        for virtual_path in virtual_path_list:
            result.update(_check_file_path(virtual_path))
    return result, sorted(result)


def _check_file_path(file_path: str) -> dict[str, list[str]]:
    for search_function in (_check_for_files, _check_for_directories, _find_files):
        results = search_function(file_path)
        if results:
            return results
    return {}


def _find_files(file_path: str) -> dict[str, list[str]]:
    files, _ = _find_regex(file_path.encode(), FILES_REGEX)
    return files


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


def _find_regex(search_term: bytes, regex_dict: dict[str, re.Pattern]) -> tuple[dict[str, list[str]], list[str]]:
    results = {}
    summary = set()
    for label, regex in regex_dict.items():
        result = regex.findall(search_term)
        if result:
            result_list = sorted({e.decode(errors='replace') for e in result})
            results.setdefault(label, []).extend(result_list)
            summary.add(label)
    return results, list(summary)

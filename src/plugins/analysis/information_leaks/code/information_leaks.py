import re
from itertools import chain

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject

PATH_REGEX = {
    'user_paths': re.compile(rb'/home/[^/%]+/[^\n \x00]+'),
    'root_path': re.compile(rb'/root/[^/%]+/[^\n \x00]+'),
    'www_path': re.compile(rb'/var/www/[^/%]+/[^\n \x00]+')
}

FILES_REGEX = {
    'any_history': re.compile(rb'.+_history')
}

PATH_ARTIFACT_DICT = {
    '.git/config': 'git_config',
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
    '.cywrk': 'cydesigner_config'
}

DIRECTORY_DICT = {
    '.git': 'git_repository',
    '.github': 'github_config_directory',
    '.pytest_cache': 'pytest_cache_directory',
    '.conda': 'conda_directory',
    '.config': 'a_config_directory',
    '.subversion': 'svn_user_settings_directory',
    'subversion': 'svn_settings_directory',
    '.idea': 'pycharm_config_directory'
}


class AnalysisPlugin(AnalysisBasePlugin):
    """
    This Plugin searches for leaked information in a firmware,
        e.g., compilation artifacts, VCS repositories, IDE configs and special paths
    """
    NAME = 'information_leaks'
    DEPENDENCIES = []
    DESCRIPTION = 'Find leaked information like compilation artifacts'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib', 'text/plain']
    VERSION = '0.1'
    FILE = __file__

    def process_object(self, file_object: FileObject):
        file_object.processed_analysis[self.NAME] = {}
        file_object.processed_analysis[self.NAME]['result'] = {}
        if file_object.processed_analysis['file_type']['result']['mime'] == 'text/plain':
            self._find_artifacts(file_object)
            file_object.processed_analysis[self.NAME]['summary'] = sorted(
                file_object.processed_analysis[self.NAME]['result'])
        else:
            self._find_regex(file_object, file_object.binary, PATH_REGEX)
            file_object.processed_analysis[self.NAME]['summary'] = sorted(
                chain(*file_object.processed_analysis[self.NAME]['result'].values()))
        return file_object

    def _find_artifacts(self, file_object: FileObject):
        for virtual_path_list in file_object.virtual_file_path.values():
            for virtual_path in virtual_path_list:
                match = self._check_for_files(file_object, virtual_path.split('|')[-1])
                if match:
                    continue
                match = self._check_for_directories(file_object, virtual_path.split('|')[-1])
                if match:
                    continue
                self._find_regex(file_object, virtual_path.split('|')[-1].encode(), FILES_REGEX)

    def _check_for_files(self, file_object: FileObject, file_path: str):
        for key_path, artifact in PATH_ARTIFACT_DICT.items():
            if file_path.endswith(key_path):
                file_object.processed_analysis[self.NAME]['result'].setdefault(artifact, []).append(file_path)
                return True
        return False

    def _check_for_directories(self, file_object: FileObject, file_path: str):
        for key_path, artifact in DIRECTORY_DICT.items():
            file_path_list = file_path.split('/')
            if len(file_path_list) > 1:
                if file_path_list[-2] == key_path:
                    file_object.processed_analysis[self.NAME]['result'].setdefault(artifact, []).append(file_path)
                    return True
        return False

    def _find_regex(self, file_object: FileObject, search_term, regex_dict):
        for label, regex in regex_dict.items():
            result = regex.findall(search_term)
            if result:
                result_list = sorted({e.decode(errors='replace') for e in result})
                file_object.processed_analysis[self.NAME]['result'].setdefault(label, []).extend(result_list)

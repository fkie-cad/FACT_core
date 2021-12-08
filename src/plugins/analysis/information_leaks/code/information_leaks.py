import re

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject

PATH_REGEX = {'user_paths': re.compile(rb'/home/[^/]+/[^\n \x00]+'),
              'root_path': re.compile(rb'/root/[^/]+/[^\n \x00]+'),
              'var_path': re.compile(rb'/var/www/[^/]+/[^\n \x00]+')
              }

PATH_ARTIFACT_DICT = {
    '.git/config': 'git_repo',
    '.conda/environments.txt': 'conda_environment',
    'default.conf': 'possible_code_blocks_config',
    'clion64.exe.vmoptions': 'clion_jvm_options',
    'idea.properties': 'clion_platform_properties',
    '.config/Code/User/settings.json': 'vscode_settings',

    '.cproject': 'eclipse_config',
    '.csproject': 'eclipse_config',
    '.project': 'eclipse_config',

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
    '.git': 'git_config_repo',
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
    This Plugin searches for compilation artifacts in a firmware,
        e.g., github repositories, IDE configs and special paths
    """
    NAME = 'information_leaks'
    DEPENDENCIES = []
    DESCRIPTION = 'Find leaked information like compilation artifacts'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib', 'text/plain']
    VERSION = '0.1'

    def __init__(self, plugin_administrator, config=None, recursive=True, offline_testing=False):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__,
                         offline_testing=offline_testing)

    def process_object(self, file_object: FileObject):
        if file_object.processed_analysis['file_type']['mime'] == 'text/plain':
            self._find_artifacts(file_object)
        else:
            for label, regex in PATH_REGEX.items():
                self._find_paths(file_object, regex, label)
        file_object.processed_analysis[self.NAME]['summary'] = list(file_object.processed_analysis[self.NAME])
        return file_object

    def _find_artifacts(self, file_object: FileObject):
        for virtual_path_list in file_object.virtual_file_path.values():
            for virtual_path in virtual_path_list:
                self._check_for_files(virtual_path, file_object)
                self._check_for_directories(virtual_path, file_object)

    def _check_for_files(self, virtual_path, file_object):
        for key_path, artifact in PATH_ARTIFACT_DICT.items():
            if virtual_path.endswith(key_path):
                file_object.processed_analysis[self.NAME][artifact] = file_object.binary.decode()

    def _check_for_directories(self, virtual_path, file_object):
        for key_path, artifact in DIRECTORY_DICT.items():
            v_path = virtual_path.split('/')
            if len(v_path) > 1:
                if v_path[-2] == key_path:
                    file_object.processed_analysis[self.NAME][artifact] = virtual_path

    def _find_paths(self, file_object: FileObject, regex, label):
        result = regex.findall(file_object.binary)
        if result:
            file_object.processed_analysis[self.NAME][label] = sorted({e.decode(errors='replace') for e in result})

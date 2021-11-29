import re

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject

PATH_REGEX = {'user_paths': re.compile(rb'/home/[^/]+/[^\n \x00]+')}

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

PATH_PATH_DICT = {
    '.github': 'github_config_directory',
    '.pytest_cache': 'pytest_cache_directory',
    '.subversion': 'svn_user_settings_directory',
    'subversion': 'svn_settings_directory',
    '.idea': 'pycharm_config_directory'
}


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    This Plugin creates several hashes of the file
    '''
    NAME = 'information_leaks'
    DEPENDENCIES = []
    DESCRIPTION = 'Find leaked information like compilation artifacts'
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib', 'text/plain']
    VERSION = '0.1'

    def __init__(self, plugin_administrator, config=None, recursive=True, offline_testing=False):
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__,
                         offline_testing=offline_testing)

    def process_object(self, file_object: FileObject):
        file_object.processed_analysis[self.NAME]['summary'] = []
        for label, regex in PATH_REGEX.items():
            self._find_paths(file_object, regex, label)

        self._find_artifacts(file_object)

        return file_object

    def _find_artifacts(self, file_object: FileObject):
        for virtual_path_list in file_object.virtual_file_path.values():
            for virtual_path in virtual_path_list:
                path = virtual_path.split('|')[-1]
                for key_path, artifact in PATH_ARTIFACT_DICT.items():
                    if path.endswith(key_path):
                        file_object.processed_analysis[self.NAME][artifact] = file_object.binary.decode()
                for key_path, artifact in PATH_PATH_DICT.items():
                    if path.endswith(key_path):
                        file_object.processed_analysis[self.NAME][artifact] = path

    def _find_paths(self, file_object: FileObject, regex, label):
        result = regex.findall(file_object.binary)
        if result:
            file_object.processed_analysis[self.NAME][label] = sorted({e.decode(errors='replace') for e in result})
            file_object.processed_analysis[self.NAME]['summary'].append(label)

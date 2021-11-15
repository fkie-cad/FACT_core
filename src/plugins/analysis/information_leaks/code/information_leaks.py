import re

from analysis.PluginBase import AnalysisBasePlugin
from objects.file import FileObject

PATH_REGEX = {'user_paths': re.compile(rb'/home/[^/]+/[^\n \0]+'),
              'proc_paths': re.compile(rb'/proc/[^/]+/[^\n \0]+')}


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
                self.test_for_ides(path, file_object)
                self.test_for_programming_environemnts(path, file_object)
                self.test_for_versioncontrol(path, file_object)

    def test_for_versioncontrol(self, path, file_object):
        if path.endswith('.git/config'):
            file_object.processed_analysis[self.NAME]['git_repo'] = file_object.binary.decode()
        elif path.endswith('.github'):
            file_object.processed_analysis[self.NAME]['github_config_directory'] = path
        elif path.endswith('.pytest_cache'):
            file_object.processed_analysis[self.NAME]['pytest_cache_directory'] = path

        # todo folders
        elif path.endswith('.subversion'):
            file_object.processed_analysis[self.NAME]['svn_user_settings_directory'] = path
        elif path.endswith('subversion'):
            file_object.processed_analysis[self.NAME]['svn_settings_directory'] = path

    def test_for_programming_environemnts(self, path, file_object):
        if path.endswith('.conda/environments.txt'):
            file_object.processed_analysis[self.NAME]['conda_environment'] = file_object.binary.decode()
        # todo java?

    def test_for_ides(self, path, file_object):
        # todo pycharm
        if path.endswith('.idea'):
            file_object.processed_analysis[self.NAME]['pycharm_config_directory'] = path

        elif path.endswith('default.conf'):
            file_object.processed_analysis[self.NAME][
                'possible_code_blocks_config'] = file_object.binary.decode()
        elif path.endswith('clion64.exe.vmoptions'):
            file_object.processed_analysis[self.NAME]['clion_jvm_options'] = file_object.binary.decode()
        elif path.endswith('idea.properties'):
            file_object.processed_analysis[self.NAME]['clion_platform_properties'] = file_object.binary.decode()
        elif path.endswith('.config/Code/User/settings.json'):
            file_object.processed_analysis[self.NAME]['vscode_settings'] = file_object.binary.decode()
        elif path.endswith('.project') or path.endswith('.cproject') or path.endswith('.ccsproject'):
            file_object.processed_analysis[self.NAME]['eclipse_config'] = file_object.binary.decode()
        else:
            self.test_embedded_ides(path, file_object)

    def test_embedded_ides(self, path, file_object):
        if path.endswith('.hws'):
            file_object.processed_analysis[self.NAME]['renesas_project_config'] = file_object.binary.decode()
        elif path.endswith('.ewd') or path.endswith('.ewp') or path.endswith('.eww') or path.endswith('.ewt'):
            file_object.processed_analysis[self.NAME][
                'iar_embedded_workbench_config'] = file_object.binary.decode()
        elif path.endswith('.Uv2') or path.endswith('.uvproj') or path.endswith('.uvopt') or path.endswith(
                '.uvprojx') or path.endswith('.uvoptx'):
            file_object.processed_analysis[self.NAME]['keil_uvision_config'] = file_object.binary.decode()
        elif path.endswith('.atsln'):
            file_object.processed_analysis[self.NAME]['atmel_studio_config'] = file_object.binary.decode()
        elif path.endswith('.cyprj') or path.endswith('.cywrk'):
            file_object.processed_analysis[self.NAME]['cydesigner_config'] = file_object.binary.decode()

    def _find_paths(self, file_object: FileObject, regex, label):
        result = regex.findall(file_object.binary)
        if result:
            file_object.processed_analysis[self.NAME][label] = sorted({e.decode(errors='replace') for e in result})
            file_object.processed_analysis[self.NAME]['summary'].append(label)

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

        self._find_git_repos(file_object)

        return file_object

    def _find_git_repos(self, file_object):
        for virtual_path_list in file_object.virtual_file_path.values():
            for virtual_path in virtual_path_list:
                path = virtual_path.split('|')[-1]
                if path.endswith('.git/config'):
                    file_object.processed_analysis[self.NAME]['git_repo'] = file_object.binary.decode()
                if path.endswith('default.conf'):
                    file_object.processed_analysis[self.NAME]['possible_code_blocks_config'] = file_object.binary.decode()
                if path.endswith('clion64.exe.vmoptions'):
                    file_object.processed_analysis[self.NAME]['clion_jvm_options'] = file_object.binary.decode()
                if path.endswith('idea.properties'):
                    file_object.processed_analysis[self.NAME]['clion_platform_properties'] = file_object.binary.decode()
                if path.endswith('.config/Code/User/settings.json'):
                    file_object.processed_analysis[self.NAME]['vscode_settings'] = file_object.binary.decode()

                if any(file_object.files_included):
                    # file_object is a diretory
                    if path.endswith('.pytest_cache'):
                        file_object.processed_analysis[self.NAME]['pytest_cache_directory'] = path
                    if path.endswith('.github'):
                        file_object.processed_analysis[self.NAME]['github_config_directory'] = path
                    if path.endswith('.idea'):
                        file_object.processed_analysis[self.NAME]['pycharm_config_directory'] = path
                    if path.endswith('.subversion'):
                        file_object.processed_analysis[self.NAME]['svn_user_settings_directory'] = path
                    if path.endswith('subversion'):
                        file_object.processed_analysis[self.NAME]['svn_settings_directory'] = path

    def _find_paths(self, file_object: FileObject, regex, label):
        
        result = regex.findall(file_object.binary)  #todo here fault
        print(result)
        if result:
            file_object.processed_analysis[self.NAME][label] = sorted({e.decode() for e in result})
            file_object.processed_analysis[self.NAME]['summary'].append(label)

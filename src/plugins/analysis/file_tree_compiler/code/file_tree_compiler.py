from common_helper_process import execute_shell_command_get_return_code

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'file_tree_compiler'
    DESCRIPTION = 'get the device tree in text from from the device tree blob'
    DEPENDENCIES = []
    VERSION = '0.1'
    # TODO MIME_WHITELIST = ?
    # TODO installation

    def __init__(self, plugin_adminstrator, config=None, recursive=True):
        self.config = config

        super().__init__(plugin_adminstrator, config=config,
                         recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):

        file_name = file_object.file_name
        file_tree = ''
        if file_name.endswith('.dtb'):
            file_tree = self.execute_file_tree_compiler(file_object.file_path)

        # store the results
        file_object.processed_analysis[self.NAME] = dict()
        file_object.processed_analysis[self.NAME]['file_tree'] = file_tree

        if file_tree != '':
            file_object.processed_analysis[self.NAME]['summary'] = [
                'file tree source available']

        return file_object

    def execute_file_tree_compiler(self, file_path):
        ftc_result, return_code = execute_shell_command_get_return_code(f'dtc -I dtb -O dts {file_path}')
        if return_code != 0:
            raise ValueError(f'The Device Tree Compiler exited with non-zero return code {return_code} after working on {file_path}')
        return ftc_result

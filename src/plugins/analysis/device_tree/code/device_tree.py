import logging

from common_helper_process import execute_shell_command_get_return_code

from analysis.PluginBase import AnalysisBasePlugin


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Device Tree Plug-in
    '''
    NAME = 'device_tree'
    DESCRIPTION = 'get the device tree in text from the device tree blob'
    DEPENDENCIES = []
    VERSION = '0.1'
    # MIME_WHITELIST = ['linux/device-tree']

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config

        super().__init__(plugin_administrator, config=config,
                         recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):

        device_tree = self.execute_device_tree_compiler(file_object.file_path)

    # store the results
        file_object.processed_analysis[self.NAME] = {}

        if device_tree:
            file_object.processed_analysis[self.NAME]['device_tree'] = device_tree
            file_object.processed_analysis[self.NAME]['summary'] = ['device tree found']
        else:
            file_object.processed_analysis[self.NAME]['warning'] = 'device tree conversion failed'

        return file_object

    def execute_device_tree_compiler(self, file_path):
        dtc_result, return_code = execute_shell_command_get_return_code(f'dtc -I dtb -O dts {file_path}')
        if return_code != 0:
            logging.warning(f'The Device Tree Compiler exited with non-zero return code {return_code} after working on {file_path}')
            return None
        return dtc_result

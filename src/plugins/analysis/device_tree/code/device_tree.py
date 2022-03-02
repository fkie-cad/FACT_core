import logging
from pathlib import Path
from typing import Optional, Union

from common_helper_process import execute_shell_command_get_return_code

from analysis.PluginBase import AnalysisBasePlugin
from plugins.mime_blacklists import MIME_BLACKLIST_COMPRESSED

FILE_TREE_MAGIC = b'\xD0\x0D\xFE\xED'  # D00DFEED


class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Device Tree Plug-in
    '''
    NAME = 'device_tree'
    DESCRIPTION = 'get the device tree in text from the device tree blob'
    DEPENDENCIES = ['file_type']
    VERSION = '0.2'
    MIME_BLACKLIST = [*MIME_BLACKLIST_COMPRESSED, 'audio', 'image', 'video']
    FILE = __file__

    def process_object(self, file_object):
        file_object.processed_analysis[self.NAME] = {}

        if file_object.processed_analysis['file_type'].get('mime') == 'linux/device-tree':
            device_tree = self.convert_device_tree(file_object.file_path)
        elif FILE_TREE_MAGIC in file_object.binary:
            device_tree = self.dump_device_tree(file_object.file_path)
        else:  # nothing found
            return file_object

        if device_tree:
            file_object.processed_analysis[self.NAME]['device_tree'] = device_tree
            file_object.processed_analysis[self.NAME]['summary'] = ['device tree found']
        else:
            file_object.processed_analysis[self.NAME]['warning'] = 'device tree conversion failed'

        return file_object

    @staticmethod
    def convert_device_tree(file_path: Union[str, Path]) -> Optional[str]:
        dtc_result, return_code = execute_shell_command_get_return_code(f'dtc -I dtb -O dts {file_path}')
        if return_code != 0:
            logging.warning(f'The Device Tree Compiler exited with non-zero return code {return_code} after working on {file_path}')
            return None
        return dtc_result

    @staticmethod
    def dump_device_tree(file_path: Union[str, Path]) -> Optional[str]:
        output, return_code = execute_shell_command_get_return_code(f'fdtdump --scan {file_path}')
        if return_code != 0:
            return None
        return output

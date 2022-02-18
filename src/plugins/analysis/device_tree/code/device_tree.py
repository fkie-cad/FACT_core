import logging
import subprocess
from pathlib import Path
from subprocess import DEVNULL, PIPE
from typing import Optional, Union

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
    VERSION = '0.3'
    MIME_BLACKLIST = [*MIME_BLACKLIST_COMPRESSED, 'audio', 'image', 'video']

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config

        super().__init__(plugin_administrator, config=config,
                         recursive=recursive, plugin_path=__file__)

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
        dtc_process = subprocess.run(f'dtc -I dtb -O dts {file_path}', shell=True, stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
        if dtc_process.returncode != 0:
            logging.warning(f'The Device Tree Compiler exited with non-zero return code {dtc_process.returncode} after working on {file_path}')
            return None
        return dtc_process.stdout

    @staticmethod
    def dump_device_tree(file_path: Union[str, Path]) -> Optional[str]:
        fdtdump_process = subprocess.run(f'fdtdump --scan {file_path}', shell=True, stdout=PIPE, stderr=DEVNULL, universal_newlines=True)
        if fdtdump_process.returncode != 0:
            return None
        return fdtdump_process.stdout

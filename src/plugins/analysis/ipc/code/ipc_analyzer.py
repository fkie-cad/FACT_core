import json
import logging
import tempfile
from pathlib import Path

from docker.types import Mount

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.docker import run_docker_container
from objects.file import FileObject

DOCKER_IMAGE = 'ipc'

class AnalysisPlugin(AnalysisBasePlugin):
    '''
    Inter-Process Communication Analysis
    '''

    # mandatory plugin attributes:
    NAME = 'ipc_analyzer'  # name of the plugin (using snake case)
    DESCRIPTION = 'Inter-Process Communication Analysis'# a short description of the plugin
    VERSION = '0.1'  # the version of this plugin (should be updated each time the plugin is changed)
    FILE = __file__  # used internally
    
    # optional plugin attributes:
    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']
    DEPENDENCIES = ['file_type']  # list of plugin names that this plugin relies on (default: `[]`)
    TIMEOUT = 600  # 10 minutes

    def _run_ipc_analyzer_in_docker(self, file_object: FileObject) -> dict:
        tmpDir = tempfile.TemporaryDirectory()
        folder = Path('/tmp') / tmpDir.name / './results'
        mount = '/input/' + file_object.file_name
        if not folder.exists():
            folder.mkdir()
        output = folder / (file_object.file_name + '.json')
        with output.open(mode='w') as f:
            json.dump({}, f)
        result = run_docker_container(
            DOCKER_IMAGE,
            combine_stderr_stdout=True,
            timeout=self.TIMEOUT,
            command=f'{mount} /results/',
            mounts=[
                Mount('/results/', str(folder.resolve()), type='bind'),
                Mount(mount, file_object.file_path, type='bind'),
            ],
        )
        try:
            with output.open(mode='r') as f:
                data = json.load(f)
        except FileNotFoundError:
            data = {'ipcCalls': []}
        tmpDir.cleanup()
        return data 

    def _do_full_analysis(self, file_object: FileObject) -> FileObject:
        output = self._run_ipc_analyzer_in_docker(file_object)
        file_object.processed_analysis[self.NAME] = {'full': output, 'summary': list(output.keys())}
        return file_object
 
    def process_object(self, file_object: FileObject) -> FileObject:
        '''
        This function handles only ELF executables. Otherwise, it returns an empty dictionary.
        It calls the ipc docker container.
        '''
        file_object = self._do_full_analysis(file_object)
        return file_object

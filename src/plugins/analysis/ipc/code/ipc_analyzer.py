import json
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

    NAME = 'ipc_analyzer'
    DESCRIPTION = 'Inter-Process Communication Analysis'
    VERSION = '0.1'
    FILE = __file__

    MIME_WHITELIST = ['application/x-executable', 'application/x-object', 'application/x-sharedlib']
    DEPENDENCIES = ['file_type']
    TIMEOUT = 600  # 10 minutes

    def _run_ipc_analyzer_in_docker(self, file_object: FileObject) -> dict:
        with tempfile.TemporaryDirectory() as tmp_dir:
            folder = Path(tmp_dir) / 'results'
            mount = f'/input/{file_object.file_name}'
            if not folder.exists():
                folder.mkdir()
            output = folder / f'{file_object.file_name}.json'
            output.write_text(json.dumps({'ipcCalls': []}))
            run_docker_container(
                DOCKER_IMAGE,
                combine_stderr_stdout=True,
                timeout=self.TIMEOUT,
                command=f'{mount} /results/',
                mounts=[
                    Mount('/results/', str(folder.resolve()), type='bind'),
                    Mount(mount, file_object.file_path, type='bind'),
                ],
            )
            data = json.loads(output.read_text())
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

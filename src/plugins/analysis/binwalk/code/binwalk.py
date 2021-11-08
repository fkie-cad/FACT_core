import string
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List

from common_helper_process import execute_shell_command

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.config import get_temp_dir_path


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'binwalk'
    DESCRIPTION = 'binwalk signature and entropy analysis'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['audio', 'image', 'video']
    VERSION = '0.5.4'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        result = {}
        with TemporaryDirectory(prefix='fact_analysis_binwalk_', dir=get_temp_dir_path(self.config)) as tmp_dir:
            signature_analysis_result = execute_shell_command(f'(cd {tmp_dir} && xvfb-run -a binwalk -BEJ {file_object.file_path})')
            result['signature_analysis'] = signature_analysis_result

            result['summary'] = list(set(self._extract_summary(signature_analysis_result)))

            pic_path = Path(tmp_dir) / f'{Path(file_object.file_path).name}.png'
            result['entropy_analysis_graph'] = pic_path.read_bytes()

        file_object.processed_analysis[self.NAME] = result
        return file_object

    def _extract_summary(self, binwalk_output: str) -> List[str]:
        summary = []
        for line in self._iterate_valid_signature_lines(binwalk_output.splitlines()):
            signature_description = self._extract_description_from_signature_line(line.split())
            if 'entropy edge' in signature_description:
                continue
            if ',' in signature_description:
                summary.append(signature_description.split(',', maxsplit=1)[0])
            elif signature_description:
                summary.append(signature_description)

        return summary

    @staticmethod
    def _extract_description_from_signature_line(separated_by_spaces):
        return ' '.join(separated_by_spaces[2:]) if len(separated_by_spaces) > 2 else ''

    @staticmethod
    def _iterate_valid_signature_lines(output_lines):
        return (line for line in output_lines if line and line[0] in string.digits)

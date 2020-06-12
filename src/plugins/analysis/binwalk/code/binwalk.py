import os
import string
from tempfile import TemporaryDirectory

from common_helper_files import get_binary_from_file
from common_helper_process import execute_shell_command

from analysis.PluginBase import AnalysisBasePlugin
from helperFunctions.dataConversion import make_unicode_string


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'binwalk'
    DESCRIPTION = 'binwalk signature and entropy analysis'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['audio', 'image', 'video']
    VERSION = '0.5.2'

    def __init__(self, plugin_administrator, config=None, recursive=True):
        self.config = config
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=__file__)

    def process_object(self, file_object):
        result = {}
        tmp_dir = TemporaryDirectory(prefix='fact_analysis_binwalk_')
        dir_path = tmp_dir.name

        signature_analysis_result = execute_shell_command('(cd {} && xvfb-run -a binwalk -BEJ {})'.format(dir_path, file_object.file_path))
        result['signature_analysis'] = make_unicode_string(signature_analysis_result)

        result['summary'] = list(set(self._extract_summary(result['signature_analysis'])))

        pic_path = os.path.join(dir_path, '{}.png'.format(os.path.basename(file_object.file_path)))
        result['entropy_analysis_graph'] = get_binary_from_file(pic_path)

        tmp_dir.cleanup()
        file_object.processed_analysis[self.NAME] = result
        return file_object

    def _extract_summary(self, binwalk_output):
        summary = list()
        output_lines = binwalk_output.splitlines()

        for line in self._iterate_valid_signature_lines(output_lines):
            separated_by_spaces = line.split()
            signature_description = self._extract_description_from_signature_line(separated_by_spaces)
            if ',' in signature_description:
                summary.append(signature_description.split(',')[0])
            elif signature_description:
                summary.append(signature_description)

        return [entry for entry in summary if 'entropy edge' not in entry]

    @staticmethod
    def _extract_description_from_signature_line(separated_by_spaces):
        signature_description = ' '.join(separated_by_spaces[2:]) if len(separated_by_spaces) > 2 else ''
        return signature_description

    @staticmethod
    def _iterate_valid_signature_lines(output_lines):
        return (line for line in output_lines if line and line[0] in string.digits)

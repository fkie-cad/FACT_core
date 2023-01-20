from __future__ import annotations

import logging
import string
import subprocess
from base64 import b64encode
from pathlib import Path
from subprocess import PIPE, STDOUT
from tempfile import TemporaryDirectory

from analysis.PluginBase import AnalysisBasePlugin
from config import cfg


class AnalysisPlugin(AnalysisBasePlugin):

    NAME = 'binwalk'
    DESCRIPTION = 'binwalk signature and entropy analysis'
    DEPENDENCIES = []
    MIME_BLACKLIST = ['audio', 'image', 'video']
    VERSION = '0.5.5'
    FILE = __file__

    def process_object(self, file_object):
        result = {}
        with TemporaryDirectory(prefix='fact_analysis_binwalk_', dir=cfg.data_storage.temp_dir_path) as tmp_dir:
            cmd_process = subprocess.run(
                f'(cd {tmp_dir} && xvfb-run -a binwalk -BEJ {file_object.file_path})',
                shell=True,
                stdout=PIPE,
                stderr=STDOUT,
                text=True,
            )
            signature_analysis_result = cmd_process.stdout
            try:
                pic_path = Path(tmp_dir) / f'{Path(file_object.file_path).name}.png'
                result['entropy_analysis_graph'] = b64encode(pic_path.read_bytes()).decode()
                result['signature_analysis'] = signature_analysis_result
                result['summary'] = list(set(self._extract_summary(signature_analysis_result)))
            except FileNotFoundError:
                result = {'failed': 'Binwalk analysis failed'}
                logging.error(f'Binwalk analysis on {file_object.uid} failed:\n{signature_analysis_result}')

        file_object.processed_analysis[self.NAME] = result
        return file_object

    def _extract_summary(self, binwalk_output: str) -> list[str]:
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

from __future__ import annotations  # noqa: N999

import logging
import re
import subprocess
from pathlib import Path

import yaml
from yaml.parser import ParserError

from analysis.PluginBase import AnalysisBasePlugin, PluginInitException
from helperFunctions.fileSystem import get_src_dir


class YaraBasePlugin(AnalysisBasePlugin):
    """
    This should be the base for all YARA based analysis plugins
    """

    NAME = 'Yara_Base_Plugin'
    DESCRIPTION = 'this is a Yara plugin'
    VERSION = '0.0'
    FILE = None

    def __init__(self, view_updater=None):
        """
        recursive flag: If True recursively analyze included files
        propagate flag: If True add analysis result of child to parent object
        """
        self.signature_path = self._get_signature_file(self.FILE) if self.FILE else None
        if self.signature_path and not Path(self.signature_path).exists():
            raise PluginInitException(
                f'Signature file {self.signature_path} not found. Did you run "compile_yara_signatures.py"?',
                plugin=self,
            )
        self.SYSTEM_VERSION = self.get_yara_system_version()
        super().__init__(view_updater=view_updater)

    def get_yara_system_version(self):
        with subprocess.Popen(['yara', '--version'], stdout=subprocess.PIPE) as process:
            yara_version = process.stdout.readline().decode().strip()

        access_time = int(Path(self.signature_path).stat().st_mtime)
        return f'{yara_version}-{access_time}'

    def process_object(self, file_object):
        if self.signature_path is not None:
            compiled_flag = '-C' if Path(self.signature_path).read_bytes().startswith(b'YARA') else ''
            command = f'yara {compiled_flag} --print-meta --print-strings {self.signature_path} {file_object.file_path}'
            with subprocess.Popen(command, shell=True, stdout=subprocess.PIPE) as process:
                output = process.stdout.read().decode()
            try:
                result = self._parse_yara_output(output)
                file_object.processed_analysis[self.NAME] = result
                file_object.processed_analysis[self.NAME]['summary'] = list(result.keys())
            except (ValueError, TypeError):
                file_object.processed_analysis[self.NAME] = {'failed': 'Processing corrupted. Likely bad call to yara.'}
        else:
            file_object.processed_analysis[self.NAME] = {'failed': 'Signature path not set'}
        return file_object

    @staticmethod
    def _get_signature_file_name(plugin_path):
        return plugin_path.split('/')[-3] + '.yc'

    def _get_signature_file(self, plugin_path):
        sig_file_name = self._get_signature_file_name(plugin_path)
        return str(Path(get_src_dir()) / 'analysis/signatures' / sig_file_name)

    @staticmethod
    def _parse_yara_output(output):
        resulting_matches = {}

        match_blocks, rules = _split_output_in_rules_and_matches(output)

        matches_regex = re.compile(r'((0x[a-f0-9]*):(\$[a-zA-Z0-9_]+):\s(.+))+')
        for index, rule in enumerate(rules):
            for match in matches_regex.findall(match_blocks[index]):
                _append_match_to_result(match, resulting_matches, rule)

        return resulting_matches


def _split_output_in_rules_and_matches(output):
    split_regex = re.compile(r'\n*.*\[.*\]\s/.+\n*')
    match_blocks = split_regex.split(output)
    while '' in match_blocks:
        match_blocks.remove('')

    rule_regex = re.compile(r'(\w*)\s\[(.*)\]\s([.]{0,2}/)(.+)')
    rules = rule_regex.findall(output)

    if not len(match_blocks) == len(rules):
        raise ValueError()
    return match_blocks, rules


def _append_match_to_result(match, resulting_matches: dict[str, dict], rule):
    rule_name, meta_string, _, _ = rule
    _, offset, matched_tag, matched_string = match
    resulting_matches.setdefault(
        rule_name, {'rule': rule_name, 'matches': True, 'strings': [], 'meta': _parse_meta_data(meta_string)}
    )
    resulting_matches[rule_name]['strings'].append((int(offset, 16), matched_tag, matched_string))


def _parse_meta_data(meta_data_string: str) -> dict[str, str | bool | int]:
    '''
    Will be of form 'item0=lowercaseboolean0,item1="str1",item2=int2,...'
    '''
    try:
        # YARA insert backslashes before single quotes in the meta output and the YAML parser doesn't like that
        meta_data_string = meta_data_string.replace(r"\'", "'")
        meta_data = yaml.safe_load(f'{{{meta_data_string.replace("=", ": ")}}}')
        assert isinstance(meta_data, dict)
        return meta_data
    except (ParserError, AssertionError):
        logging.warning(f"Malformed meta string '{meta_data_string}'")
        return {}

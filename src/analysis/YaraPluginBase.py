import json
import logging
import re
import subprocess
from pathlib import Path

from analysis.PluginBase import AnalysisBasePlugin, PluginInitException
from helperFunctions.fileSystem import get_src_dir


class YaraBasePlugin(AnalysisBasePlugin):
    '''
    This should be the base for all YARA based analysis plugins
    '''
    NAME = 'Yara_Base_Plugin'
    DESCRIPTION = 'this is a Yara plugin'
    VERSION = '0.0'

    def __init__(self, plugin_administrator, config=None, recursive=True, plugin_path=None):
        '''
        recursive flag: If True recursively analyze included files
        propagate flag: If True add analysis result of child to parent object
        '''
        self.config = config
        self.signature_path = self._get_signature_file(plugin_path) if plugin_path else None
        if self.signature_path and not Path(self.signature_path).exists():
            logging.error('Signature file {} not found. Did you run "compile_yara_signatures.py"?'.format(self.signature_path))
            raise PluginInitException(plugin=self)
        self.SYSTEM_VERSION = self.get_yara_system_version()
        super().__init__(plugin_administrator, config=config, recursive=recursive, plugin_path=plugin_path)

    def get_yara_system_version(self):
        with subprocess.Popen(['yara', '--version'], stdout=subprocess.PIPE) as process:
            yara_version = process.stdout.readline().decode().strip()

        access_time = int(Path(self.signature_path).stat().st_mtime)
        return '{}_{}'.format(yara_version, access_time)

    def process_object(self, file_object):
        if self.signature_path is not None:
            with subprocess.Popen('yara --print-meta --print-strings {} {}'.format(self.signature_path, file_object.file_path), shell=True, stdout=subprocess.PIPE) as process:
                output = process.stdout.read().decode()
            try:
                result = self._parse_yara_output(output)
                file_object.processed_analysis[self.NAME] = result
                file_object.processed_analysis[self.NAME]['summary'] = list(result.keys())
            except (ValueError, TypeError):
                file_object.processed_analysis[self.NAME] = {'ERROR': 'Processing corrupted. Likely bad call to yara.'}
        else:
            file_object.processed_analysis[self.NAME] = {'ERROR': 'Signature path not set'}
        return file_object

    @staticmethod
    def _get_signature_file_name(plugin_path):
        return plugin_path.split('/')[-3] + '.yc'

    def _get_signature_file(self, plugin_path):
        sig_file_name = self._get_signature_file_name(plugin_path)
        return str(Path(get_src_dir()) / 'analysis/signatures' / sig_file_name)

    @staticmethod
    def _parse_yara_output(output):
        resulting_matches = dict()

        match_blocks, rules = _split_output_in_rules_and_matches(output)

        matches_regex = re.compile(r'((0x[a-f0-9]*):(\S+):\s(.+))+')
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


def _append_match_to_result(match, resulting_matches, rule):
    rule_name, meta_string, _, _ = rule
    _, offset, matched_tag, matched_string = match

    meta_dict = _parse_meta_data(meta_string)

    this_match = resulting_matches[rule_name] if rule_name in resulting_matches else dict(rule=rule_name, matches=True, strings=list(), meta=meta_dict)

    this_match['strings'].append((int(offset, 16), matched_tag, matched_string.encode()))
    resulting_matches[rule_name] = this_match


def _parse_meta_data(meta_data_string):
    '''
    Will be of form 'item0=lowercaseboolean0,item1="value1",item2=value2,..'
    '''
    meta_data = dict()
    for item in meta_data_string.split(','):
        if '=' in item:
            key, value = item.split('=', maxsplit=1)
            value = json.loads(value) if value in ['true', 'false'] else value.strip('"')
            meta_data[key] = value
        else:
            logging.warning('Malformed meta string \'{}\''.format(meta_data_string))
    return meta_data

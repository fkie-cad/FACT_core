import logging
import os
from tempfile import TemporaryDirectory
from typing import List

from common_helper_files import get_files_in_dir
from common_helper_yara import compile_rules, get_all_matched_strings, scan


class SignatureTestingMatching:

    def __init__(self):
        self.tmp_dir = TemporaryDirectory(prefix='fact_software_signature_test')
        self.signature_file_path = os.path.join(self.tmp_dir.name, 'test_sig.yc')
        self.matches = []
        self.test_file = None
        self.signature_path = None
        self.strings_to_match = None

    def check(self, signature_path, test_file):
        self.test_file = test_file
        self.signature_path = signature_path
        self._get_list_of_test_data()
        self._execute_yara_matching()
        return self._intersect_lists()

    def _execute_yara_matching(self):
        compile_rules(self.signature_path, self.signature_file_path, external_variables={'test_flag': 'true'})
        scan_result = scan(self.signature_file_path, self.test_file)
        self.matches = get_all_matched_strings(scan_result)

    def _get_list_of_test_data(self):
        with open(self.test_file, mode='r', encoding='utf8') as pointer:
            self.strings_to_match = pointer.read().split('\n')
        self.strings_to_match.pop()

    def _intersect_lists(self):
        strings_to_match = set(self.strings_to_match)
        return strings_to_match.difference(self.matches)


class SignatureTestingMeta:
    META_FIELDS = ['software_name', 'open_source', 'website', 'description']
    missing_meta_fields = []

    def check_meta_fields(self, sig_path):
        sig_dir = sig_path
        list_of_files = get_files_in_dir(sig_dir)
        for file in list_of_files:
            self.check_for_file(file)
        return self.missing_meta_fields

    def check_for_file(self, file_path):
        with open(file_path, 'r') as fd:
            raw = fd.read()
        rules = self._split_rules(raw)
        for rule in rules:
            self.check_meta_fields_of_rule(rule)

    @staticmethod
    def _split_rules(raw_rules: str) -> List[str]:
        rule_lines = raw_rules.splitlines()
        rule_start_indices = [
            i
            for i in range(len(rule_lines))
            if rule_lines[i].startswith('rule ')
        ]
        rules = [
            ''.join(rule_lines[start:end])
            for start, end in zip(rule_start_indices, rule_start_indices[1:] + [len(rule_lines)])
        ]
        return rules

    def check_meta_fields_of_rule(self, rule: str):
        rule_components = [s.strip() for s in rule.split()]
        rule_name = rule_components[1].replace('{', '')
        if 'meta:' not in rule_components:
            self._register_missing_field('ALL', rule_name)
            return
        for required_field in self.META_FIELDS:
            if required_field not in rule_components:
                self._register_missing_field(required_field, rule_name)

    def _register_missing_field(self, missing_field: str, rule_name: str):
        self.missing_meta_fields.append('{} in {}'.format(missing_field, rule_name))
        logging.error('CST: No meta field {} for rule {}.'.format(missing_field, rule_name))

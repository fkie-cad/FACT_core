# pylint: disable=no-self-use
import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import List

from common_helper_yara import compile_rules, get_all_matched_strings, scan


class SignatureTestingMatching:

    def __init__(self):
        self.matches = []
        self.test_file = None
        self.signature_path = None
        self.strings_to_match = None

    def check(self, signature_path: Path, test_file: Path):
        self.test_file = test_file
        self.signature_path = signature_path
        self.strings_to_match = test_file.read_text().strip().split('\n')
        self._execute_yara_matching()
        return set(self.strings_to_match).difference(self.matches)

    def _execute_yara_matching(self):
        with TemporaryDirectory(prefix='fact_software_signature_test') as tmp_dir:
            signature_file_path = Path(tmp_dir) / 'test_sig.yc'
            compile_rules(self.signature_path, signature_file_path, external_variables={'test_flag': 'true'})
            scan_result = scan(signature_file_path, self.test_file, compiled=True)
            self.matches = get_all_matched_strings(scan_result)


class SignatureTestingMeta:
    META_FIELDS = ['software_name', 'open_source', 'website', 'description']
    missing_meta_fields = []

    def check_meta_fields(self, sig_path: Path):
        for file in sig_path.iterdir():
            self.check_for_file(file)
        return self.missing_meta_fields

    def check_for_file(self, file_path: Path):
        rules = self._split_rules(file_path.read_text())
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
        self.missing_meta_fields.append(f'{missing_field} in {rule_name}')
        logging.error(f'CST: No meta field {missing_field} for rule {rule_name}.')

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import yara

from helperFunctions.yara import compile_rules, get_all_matched_strings, scan_file


class SignatureTestingMatching:
    def __init__(self):
        self.matches = []
        self.test_file = None
        self.signature_path = None
        self.strings_to_match = None

    def check(self, signature_path: Path, test_file: Path) -> set[str]:
        self.test_file = test_file
        self.signature_path = signature_path
        self.strings_to_match = test_file.read_text().strip().split('\n')
        self._execute_yara_matching()
        return set(self.strings_to_match).difference(self.matches)

    def _execute_yara_matching(self) -> None:
        with TemporaryDirectory(prefix='fact_software_signature_test') as tmp_dir:
            signature_file_path = Path(tmp_dir) / 'test_sig.yc'
            compile_rules(self.signature_path, signature_file_path, external_variables={'test_flag': 'true'})
            scan_result = scan_file(signature_file_path, self.test_file)
            self.matches = get_all_matched_strings(scan_result)


class SignatureTestingMeta:
    META_FIELDS = ('software_name', 'open_source', 'website', 'description')

    def check_meta_fields(self, sig_path: Path) -> tuple[list[str], list[str]]:
        missing_meta_fields = []
        rule_errors = []
        for file in sig_path.iterdir():
            try:
                missing_meta_fields.extend(self._check_for_file(file))
            except yara.SyntaxError as error:
                rule_errors.append(f'error in rule file {file.name}: {error}')
        return missing_meta_fields, rule_errors

    def _check_for_file(self, file_path: Path) -> list[str]:
        missing_meta_fields = []
        rules = yara.compile(str(file_path))
        for rule in rules:
            missing_meta_fields.extend(self.check_meta_fields_of_rule(rule))
        return missing_meta_fields

    def check_meta_fields_of_rule(self, rule: yara.Rule) -> list[str]:
        if not rule.meta:
            return [f'ALL in {rule.identifier}']
        return [
            f'{required_field} in {rule.identifier}'
            for required_field in self.META_FIELDS
            if required_field not in rule.meta
        ]

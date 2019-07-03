import logging
import os
from tempfile import TemporaryDirectory

from common_helper_files import get_files_in_dir
from common_helper_yara import compile_rules, get_all_matched_strings, scan


class SignatureTestingMatching():

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
        with open(self.test_file, mode='r', encoding="utf8") as pointer:
            self.strings_to_match = pointer.read().split("\n")
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
        rules = raw.split('{')
        self.check_for_rules(rules)

    def check_for_rules(self, rules):
        last_rule = rules.pop(0).split().pop()
        for rule in rules:
            fields = rule.split()
            if "meta:" not in fields:
                self.missing_meta_fields.append("ALL in {}".format(last_rule))
                logging.error("CST: No meta fields for rule {}.".format(last_rule))
            else:
                for field in self.META_FIELDS:
                    logging.info("Checking {} in {}.".format(field, last_rule))
                    if not check_field(field, fields):
                        self.missing_meta_fields.append("{} in {}".format(field, last_rule))
                        logging.error("CST: No meta field {} for rule {}.".format(field, last_rule))

            last_rule = rule.split().pop()


def check_field(field, fields):
    return field in fields

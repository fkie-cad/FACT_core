from os.path import basename
from subprocess import check_output, CalledProcessError, STDOUT
from tempfile import NamedTemporaryFile
import yara


class YaraRuleError(Exception):
    pass


class YaraBinarySearchScanner:

    def __init__(self, config=None):
        self.matches = []
        self.config = config
        self.db_path = self.config['data_storage']['firmware_file_storage_directory']

    def _execute_yara_search(self, rule_file_path):
        '''
        scans the (whole) db directory with the provided rule file and returns the (raw) results
        yara-python cannot be used, because it (currently) supports single-file scanning only
        :param rule_file_path: file path to yara rule file
        :return: output from yara scan
        '''
        try:
            scan_result = check_output('yara -r {} {}'.format(rule_file_path, self.db_path), shell=True, stderr=STDOUT)
        except CalledProcessError as e:
            raise YaraRuleError('There seems to be an error in the rule file:\n{}'.format(e.output.decode()))
        return scan_result

    @staticmethod
    def _parse_raw_result(raw_result):
        '''
        :param raw_result: raw yara scan result
        :return: dict of matching rules with lists of matched UIDs as values
        '''
        results = {}
        for line in raw_result.split(b'\n'):
            if line and b'warning' not in line:
                rule, match = line.decode().split(' ')
                match = basename(match)
                if rule in results:
                    results[rule].append(match)
                else:
                    results[rule] = [match]
        return results

    @staticmethod
    def _eliminate_duplicates(result_dict):
        for key in result_dict:
            result_dict[key] = sorted(set(result_dict[key]))

    def get_binary_search_result(self, yara_rules):
        '''
        :param yara_rules: byte string with the contents of the yara rule file
        :return: dict of matching rules with lists of (unique) matched UIDs as values
        '''
        with NamedTemporaryFile() as temp_rule_file:
            temp_rule_file.write(yara_rules)
            temp_rule_file.flush()
            try:
                raw_result = self._execute_yara_search(temp_rule_file.name)
            except YaraRuleError as e:
                return e
            results = self._parse_raw_result(raw_result)
            if results:
                self._eliminate_duplicates(results)
            return results


def is_valid_yara_rule_file(rules_file):
    return get_yara_error(rules_file) is None


def get_yara_error(rules_file):
    if type(rules_file) == bytes:
        rules_file = rules_file.decode()
    try:
        yara.compile(source=rules_file)
        return None
    except Exception as e:
        return e

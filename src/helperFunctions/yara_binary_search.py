from os.path import basename
from subprocess import CalledProcessError
from tempfile import NamedTemporaryFile
from typing import Dict, List, Optional, Tuple

import yara
from common_helper_process import execute_shell_command

from helperFunctions.database import ConnectTo
from storage.db_interface_common import MongoInterfaceCommon
from storage.fs_organizer import FS_Organizer


class YaraBinarySearchScanner:

    def __init__(self, config=None):
        self.matches = []
        self.config = config
        self.db_path = self.config['data_storage']['firmware_file_storage_directory']

    def _execute_yara_search(self, rule_file_path, target_path=None):
        '''
        scans the (whole) db directory with the provided rule file and returns the (raw) results
        yara-python cannot be used, because it (currently) supports single-file scanning only
        :param rule_file_path: file path to yara rule file
        :return: output from yara scan
        '''
        command = 'yara -r {} {}'.format(rule_file_path, self.db_path if target_path is None else target_path)
        return execute_shell_command(command)

    def _execute_yara_search_for_single_firmware(self, rule_file_path, firmware_uid):
        with ConnectTo(YaraBinarySearchScannerDbInterface, self.config) as connection:
            file_paths = connection.get_file_paths_of_files_included_in_fo(firmware_uid)
        result = (self._execute_yara_search(rule_file_path, path) for path in file_paths)
        return '\n'.join(result)

    @staticmethod
    def _parse_raw_result(raw_result: str) -> Dict[str, List[str]]:
        '''
        :param raw_result: raw yara scan result
        :return: dict of matching rules with lists of matched UIDs as values
        '''
        results = {}
        for line in raw_result.split('\n'):
            if line and 'warning' not in line:
                rule, match = line.split(' ')
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

    def get_binary_search_result(self, task: Tuple[bytes, Optional[str]]):
        '''
        :param task: tuple containing the yara_rules (byte string with the contents of the yara rule file) and optionally a firmware uid if only the contents
                     of a single firmware are to be scanned
        :return: dict of matching rules with lists of (unique) matched UIDs as values
        '''
        with NamedTemporaryFile() as temp_rule_file:
            yara_rules, firmware_uid = task
            try:
                self._prepare_temp_rule_file(temp_rule_file, yara_rules)
                raw_result = self._get_raw_result(firmware_uid, temp_rule_file)
                results = self._parse_raw_result(raw_result)
                self._eliminate_duplicates(results)
                return results
            except yara.SyntaxError as yara_error:
                return 'There seems to be an error in the rule file:\n{}'.format(yara_error)
            except CalledProcessError as process_error:
                return 'Error when calling YARA:\n{}'.format(process_error.output.decode())

    def _get_raw_result(self, firmware_uid, temp_rule_file):
        if firmware_uid is None:
            raw_result = self._execute_yara_search(temp_rule_file.name)
        else:
            raw_result = self._execute_yara_search_for_single_firmware(temp_rule_file.name, firmware_uid)
        return raw_result

    @staticmethod
    def _prepare_temp_rule_file(temp_rule_file, yara_rules):
        compiled_rules = yara.compile(source=yara_rules.decode())
        compiled_rules.save(file=temp_rule_file)
        temp_rule_file.flush()


def is_valid_yara_rule_file(rules_file):
    return get_yara_error(rules_file) is None


def get_yara_error(rules_file):
    if isinstance(rules_file, bytes):
        rules_file = rules_file.decode()
    try:
        yara.compile(source=rules_file)
        return None
    except Exception as exception:
        return exception


class YaraBinarySearchScannerDbInterface(MongoInterfaceCommon):

    READ_ONLY = True

    def get_file_paths_of_files_included_in_fo(self, fo_uid: str) -> List[str]:
        fs_organizer = FS_Organizer(self.config)
        return [
            fs_organizer.generate_path_from_uid(uid)
            for uid in self.get_uids_of_all_included_files(fo_uid)
        ]

import subprocess
from configparser import ConfigParser
from os.path import basename
from pathlib import Path
from subprocess import PIPE, STDOUT, CalledProcessError
from tempfile import NamedTemporaryFile
from typing import Dict, List, Optional, Tuple, Union

import yara

from storage.db_interface_common import DbInterfaceCommon
from storage.fsorganizer import FSOrganizer


class YaraBinarySearchScanner:
    '''
    This class provides functionality to scan files in the database for yara patterns. The public method allows to
    either match a given set of patterns on all files in the database or focus only on files included in a single
    firmware.

    :param config: The FACT configuration.
    '''

    def __init__(self, config: ConfigParser):
        self.matches = []
        self.config = config
        self.db_path = self.config['data-storage']['firmware-file-storage-directory']
        self.db = DbInterfaceCommon()
        self.fs_organizer = FSOrganizer()

    def _execute_yara_search(self, rule_file_path: str, target_path: Optional[str] = None) -> str:
        '''
        Scans the (whole) db directory with the provided rule file and returns the (raw) results.
        Yara-python cannot be used, because it (currently) supports single-file scanning only.

        :param rule_file_path: The file path to the yara rule file.
        :return: The output from the yara scan.
        '''
        compiled_flag = '-C' if Path(rule_file_path).read_bytes().startswith(b'YARA') else ''
        command = f'yara -r {compiled_flag} {rule_file_path} {target_path or self.db_path}'
        yara_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, text=True)
        return yara_process.stdout

    def _execute_yara_search_for_single_firmware(self, rule_file_path: str, firmware_uid: str) -> str:
        file_paths = self._get_file_paths_of_files_included_in_fw(firmware_uid)
        result = (self._execute_yara_search(rule_file_path, path) for path in file_paths)
        return '\n'.join(result)

    def _get_file_paths_of_files_included_in_fw(self, fw_uid: str) -> List[str]:
        return [
            self.fs_organizer.generate_path_from_uid(uid)
            for uid in self.db.get_all_files_in_fw(fw_uid)
        ]

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
                results.setdefault(rule, []).append(basename(match))
        return results

    @staticmethod
    def _eliminate_duplicates(result_dict: Dict[str, List[str]]):
        for key in result_dict:
            result_dict[key] = sorted(set(result_dict[key]))

    def get_binary_search_result(self, task: Tuple[bytes, Optional[str]]) -> Union[Dict[str, List[str]], str]:
        '''
        Perform a yara search on the files in the database.

        :param task: A tuple containing the yara_rules (byte string with the contents of the yara rule file) and
            optionally a firmware uid if only the contents of a single firmware are to be scanned.
        :return: dict of matching rules with lists of (unique) matched UIDs as values or an error message.
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
                return f'There seems to be an error in the rule file:\n{yara_error}'
            except CalledProcessError as process_error:
                return f'Error when calling YARA:\n{process_error.output.decode()}'

    def _get_raw_result(self, firmware_uid: Optional[str], temp_rule_file: NamedTemporaryFile) -> str:
        if firmware_uid is None:
            raw_result = self._execute_yara_search(temp_rule_file.name)
        else:
            raw_result = self._execute_yara_search_for_single_firmware(temp_rule_file.name, firmware_uid)
        return raw_result

    @staticmethod
    def _prepare_temp_rule_file(temp_rule_file: NamedTemporaryFile, yara_rules: bytes):
        compiled_rules = yara.compile(source=yara_rules.decode())
        compiled_rules.save(file=temp_rule_file)
        temp_rule_file.flush()


def is_valid_yara_rule_file(yara_rules: Union[str, bytes]) -> bool:
    '''
    Check if ``yara_rules`` is a valid set of yara rules.

    :param: A string containing yara rules.
    :return: ``True`` if the rules are valid and ``False`` otherwise.
    '''
    return get_yara_error(yara_rules) is None


def get_yara_error(rules_file: Union[str, bytes]) -> Optional[Exception]:
    '''
    Get the exception that is caused by trying to compile ``rules_file`` with yara or ``None`` if there is none.

    :param rules_file: A string containing yara rules.
    :result: The exception if compiling the rules causes an exception or ``None`` otherwise.
    '''
    try:
        if isinstance(rules_file, bytes):
            rules_file = rules_file.decode()
        yara.compile(source=rules_file)
        return None
    except (yara.Error, TypeError, UnicodeDecodeError) as error:
        return error

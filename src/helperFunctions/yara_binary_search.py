from __future__ import annotations

import re
import subprocess
from pathlib import Path
from subprocess import PIPE, STDOUT, CalledProcessError
from tempfile import NamedTemporaryFile

import yara

import config
from storage.db_interface_common import DbInterfaceCommon
from storage.fsorganizer import FSOrganizer


class YaraBinarySearchScanner:
    """
    This class provides functionality to scan files in the database for yara patterns. The public method allows to
    either match a given set of patterns on all files in the database or focus only on files included in a single
    firmware.

    :param config: The FACT configuration.
    """

    def __init__(self):
        self.matches = []
        self.db_path = config.backend.firmware_file_storage_directory
        self.db = DbInterfaceCommon()
        self.fs_organizer = FSOrganizer()

    def _execute_yara_search(self, rule_file_path: str, target_path: str | None = None) -> str:
        """
        Scans the (whole) db directory with the provided rule file and returns the (raw) results.
        Yara-python cannot be used, because it (currently) supports single-file scanning only.

        :param rule_file_path: The file path to the yara rule file.
        :return: The output from the yara scan.
        """
        compiled_flag = '-C' if Path(rule_file_path).read_bytes().startswith(b'YARA') else ''
        # -r: recursive, -s: print strings, -N: no follow symlinks
        command = f'yara -r -s -N {compiled_flag} {rule_file_path} {target_path or self.db_path}'
        yara_process = subprocess.run(command, shell=True, stdout=PIPE, stderr=STDOUT, text=True, check=False)
        return yara_process.stdout

    def _execute_yara_search_for_single_firmware(self, rule_file_path: str, firmware_uid: str) -> str:
        file_paths = self._get_file_paths_of_files_included_in_fw(firmware_uid)
        result = (self._execute_yara_search(rule_file_path, path) for path in file_paths)
        return '\n'.join(result)

    def _get_file_paths_of_files_included_in_fw(self, fw_uid: str) -> list[str]:
        return [self.fs_organizer.generate_path_from_uid(uid) for uid in self.db.get_all_files_in_fw(fw_uid)]

    @staticmethod
    def _parse_raw_result(
        raw_result: str, match_limit: int = 20, match_len_limit: int = 50
    ) -> dict[str, dict[str, list[dict]]]:
        """
        YARA scan results have the following structure:
        <rule_name> <matching_file_path>
        <offset>:<condition>: <matching_string>
        <offset>:<condition>: <matching_string>
        ...
        <rule_name> <matching_file_path>
        ...

        We parse the results and put them into a dictionary of the following form:
        {
            <uid:str>: {
                <rule:str>: [
                    {
                        "offset": <offset in hex:str>,
                        "condition": <condition name:str>,
                        "match": <matching string:str>,
                    },
                    ... (max match_limit)
                ]
            },
            ...
        }

        :param raw_result: raw yara scan result
        :param match_limit: maximum number of stored strings per rule
        :param match_len_limit: maximum length of stored strings
        :return: dict of matching files, rules and strings
        """
        results = {}
        for result_str in re.findall(
            # <rule_name>            <path>     <offset>    <condition>      <string>
            r'[a-zA-Z_][a-zA-Z0-9_]+ [^\n]+\n(?:0x[0-9a-f]+:\$[a-zA-Z0-9_]+: .+\n)+',
            raw_result,
        ):
            rule_str, *match_lines = result_str.splitlines()
            rule, path_str = rule_str.split(' ', maxsplit=1)
            uid = Path(path_str).name
            results.setdefault(uid, {}).setdefault(rule, [])
            for match_line in match_lines:
                offset, condition, match_str = match_line.split(':', maxsplit=2)
                match_str = match_str[1:]  # remove the space at the beginning
                if len(match_str) > match_len_limit:
                    match_str = match_str[:match_len_limit] + '...'
                results[uid][rule].append({'offset': offset, 'condition': condition, 'match': match_str})
                if len(results[uid][rule]) >= match_limit:
                    # only collect at most <match_limit> matching strings to avoid storing loads of unnecessary data
                    # in case of very general rules with lots of matches
                    break
        return results

    def get_binary_search_result(self, task: tuple[bytes, str | None]) -> dict[str, dict[str, list[dict]]] | str:
        """
        Perform a yara search on the files in the database.

        :param task: A tuple containing the yara_rules (byte string with the contents of the yara rule file) and
            optionally a firmware uid if only the contents of a single firmware are to be scanned.
        :return: dict of matching rules with lists of (unique) matched UIDs as values or an error message.
        """
        with NamedTemporaryFile() as temp_rule_file:
            yara_rules, firmware_uid = task
            try:
                self._prepare_temp_rule_file(temp_rule_file, yara_rules)
                raw_result = self._get_raw_result(firmware_uid, temp_rule_file)
                return self._parse_raw_result(raw_result)
            except yara.SyntaxError as yara_error:
                return f'There seems to be an error in the rule file:\n{yara_error}'
            except CalledProcessError as process_error:
                return f'Error when calling YARA:\n{process_error.output.decode()}'

    def _get_raw_result(self, firmware_uid: str | None, temp_rule_file: NamedTemporaryFile) -> str:
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


def is_valid_yara_rule_file(yara_rules: str | bytes) -> bool:
    """
    Check if ``yara_rules`` is a valid set of yara rules.

    :param: A string containing yara rules.
    :return: ``True`` if the rules are valid and ``False`` otherwise.
    """
    return get_yara_error(yara_rules) is None


def get_yara_error(rules_file: str | bytes) -> Exception | None:
    """
    Get the exception that is caused by trying to compile ``rules_file`` with yara or ``None`` if there is none.

    :param rules_file: A string containing yara rules.
    :result: The exception if compiling the rules causes an exception or ``None`` otherwise.
    """
    try:
        if isinstance(rules_file, bytes):
            rules_file = rules_file.decode()
        yara.compile(source=rules_file)
        return None
    except (yara.Error, TypeError, UnicodeDecodeError) as error:
        return error

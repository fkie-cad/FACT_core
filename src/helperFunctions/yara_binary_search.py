from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile

import yara

import config
from helperFunctions.yara import Match, scan_dir, scan_files
from storage.db_interface_common import DbInterfaceCommon
from storage.fsorganizer import FSOrganizer


class YaraBinarySearchScanner:
    """
    This class provides functionality to scan files in the database for yara patterns. The public method allows to
    either match a given set of patterns on all files in the database or focus only on files included in a single
    firmware.
    FixMe: class is only used in back_end_binding -> move there
    """

    def __init__(self, db_interface: DbInterfaceCommon | None = None):
        self.matches = []
        self.db_path = config.backend.firmware_file_storage_directory
        self.db = db_interface or DbInterfaceCommon()
        self.fs_organizer = FSOrganizer()

    def _execute_yara_search_for_single_firmware(self, rule_file: Path, firmware_uid: str) -> list[Match]:
        file_paths = self._get_file_paths_of_files_included_in_fw(firmware_uid)
        return scan_files(rule_file, file_paths)

    def _get_file_paths_of_files_included_in_fw(self, fw_uid: str) -> list[str]:
        return [self.fs_organizer.generate_path_from_uid(uid) for uid in self.db.get_all_files_in_fw(fw_uid)]

    @staticmethod
    def _convert_matches_to_result(matches: list[Match]) -> dict[str, dict[str, list[dict]]]:
        result = {}
        for match in matches:
            uid = Path(match.file).name
            result.setdefault(uid, {}).setdefault(match.rule, [])
            for string_match in match.strings:
                for instance in string_match.instances:
                    # FixMe: return Match objects instead
                    result[uid][match.rule].append(
                        {
                            'offset': hex(instance.offset),
                            'condition': string_match.identifier,
                            'match': instance.matched_data.decode('utf-8', errors='ignore'),
                        }
                    )
                    if len(result[uid][match.rule]) >= config.backend.binary_search.max_strings_per_match:
                        # only collect at most <match_limit> matching strings to avoid storing loads of unnecessary data
                        # in case of very general rules with lots of matches
                        break
                else:
                    continue
                break  # break if the inner loop did (else continue)
        return result

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
                matches = self._get_matches(firmware_uid, Path(temp_rule_file.name))
                return self._convert_matches_to_result(matches)
            except yara.SyntaxError as yara_error:
                return f'There seems to be an error in the rule file:\n{yara_error}'

    def _get_matches(self, firmware_uid: str | None, rule_file: Path) -> list[Match]:
        if firmware_uid is not None:
            return self._execute_yara_search_for_single_firmware(rule_file, firmware_uid)
        return scan_dir(rule_file, Path(self.db_path))

    @staticmethod
    def _prepare_temp_rule_file(temp_rule_file: NamedTemporaryFile, yara_rules: bytes) -> None:
        compiled_rules = yara.compile(source=yara_rules.decode())
        compiled_rules.save(file=temp_rule_file)
        temp_rule_file.flush()

from __future__ import annotations

import logging
from time import time
from typing import List, Optional, Tuple

from sqlalchemy import func, select, type_coerce
from sqlalchemy.dialects.postgresql import JSONB

from helperFunctions.data_conversion import (
    convert_compare_id_to_list,
    convert_uid_list_to_compare_id,
    normalize_compare_id,
)
from helperFunctions.virtual_file_path import get_top_of_virtual_path
from storage.db_interface_base import ReadWriteDbInterface
from storage.db_interface_common import DbInterfaceCommon
from storage.schema import AnalysisEntry, ComparisonEntry, FileObjectEntry, fw_files_table


class FactComparisonException(Exception):
    def get_message(self):
        if self.args:  # pylint: disable=using-constant-test
            return self.args[0]  # pylint: disable=unsubscriptable-object
        return ''


class ComparisonDbInterface(DbInterfaceCommon, ReadWriteDbInterface):
    def add_comparison_result(self, comparison_result: dict):
        comparison_id = self._calculate_comp_id(comparison_result)
        if not self.objects_exist(comparison_id):
            logging.error(f'Could not add comparison result: not all objects found in db: {comparison_id}')
            return
        if self.comparison_exists(comparison_id):
            self.update_comparison(comparison_id, comparison_result)
        else:
            self.insert_comparison(comparison_id, comparison_result)
        logging.info(f'compare result added to db: {comparison_id}')

    def comparison_exists(self, comparison_id: str) -> bool:
        with self.get_read_only_session() as session:
            query = select(ComparisonEntry.comparison_id).filter(ComparisonEntry.comparison_id == comparison_id)
            return bool(session.execute(query).scalar())

    def objects_exist(self, compare_id: str) -> bool:
        uid_list = convert_compare_id_to_list(compare_id)
        with self.get_read_only_session() as session:
            query = select(func.count(FileObjectEntry.uid)).filter(FileObjectEntry.uid.in_(uid_list))
            return session.execute(query).scalar() == len(uid_list)

    @staticmethod
    def _calculate_comp_id(comparison_result):
        uid_set = {uid for c_dict in comparison_result['general'].values() for uid in c_dict}
        comp_id = convert_uid_list_to_compare_id(uid_set)
        return comp_id

    def get_comparison_result(self, comparison_id: str) -> Optional[dict]:
        comparison_id = normalize_compare_id(comparison_id)
        if not self.comparison_exists(comparison_id):
            logging.debug(f'Compare result not found in db: {comparison_id}')
            return None
        with self.get_read_only_session() as session:
            comparison_entry = session.get(ComparisonEntry, comparison_id)
            logging.debug(f'got compare result from db: {comparison_id}')
            return self._entry_to_dict(comparison_entry, comparison_id)

    @staticmethod
    def _entry_to_dict(comparison_entry, comparison_id):
        return {
            **comparison_entry.data,
            '_id': comparison_id,  # FixMe? for backwards compatibility. change/remove?
            'submission_date': comparison_entry.submission_date,
        }

    def update_comparison(self, comparison_id: str, comparison_result: dict):
        with self.get_read_write_session() as session:
            comparison_entry = session.get(ComparisonEntry, comparison_id)
            comparison_entry.data = comparison_result
            comparison_entry.submission_date = time()

    def insert_comparison(self, comparison_id: str, comparison_result: dict):
        with self.get_read_write_session() as session:
            comparison_entry = ComparisonEntry(
                comparison_id=comparison_id,
                submission_date=time(),
                data=comparison_result,
                file_objects=[session.get(FileObjectEntry, uid) for uid in comparison_id.split(';')],
            )
            session.add(comparison_entry)

    def page_comparison_results(self, skip=0, limit=0) -> List[Tuple[str, str, float]]:
        with self.get_read_only_session() as session:
            query = select(ComparisonEntry).order_by(ComparisonEntry.submission_date.desc())
            query = self._apply_offset_and_limit(query, skip, limit)
            return [
                (entry.comparison_id, entry.data['general']['hid'], entry.submission_date)
                for entry in session.execute(query).scalars()
            ]

    def get_total_number_of_results(self) -> int:
        with self.get_read_only_session() as session:
            query = select(func.count(ComparisonEntry.comparison_id))
            return session.execute(query).scalar()

    def get_ssdeep_hash(self, uid: str) -> str:
        with self.get_read_only_session() as session:
            analysis: AnalysisEntry = session.get(AnalysisEntry, (uid, 'file_hashes'))
            return analysis.result['ssdeep'] if analysis is not None else None

    def get_entropy(self, uid: str) -> float:
        with self.get_read_only_session() as session:
            analysis: AnalysisEntry = session.get(AnalysisEntry, (uid, 'unpacker'))
            if analysis is None or 'entropy' not in analysis.result:
                return 0.0
            return analysis.result['entropy']

    def get_exclusive_files(self, compare_id: str, root_uid: str) -> List[str]:
        if compare_id is None or root_uid is None:
            return []
        try:
            result = self.get_comparison_result(compare_id)
            exclusive_files = result['plugins']['File_Coverage']['exclusive_files'][root_uid]
        except (KeyError, FactComparisonException):
            exclusive_files = []
        return exclusive_files

    def get_vfp_of_included_text_files(self, root_uid: str, blacklist: set[str]) -> dict[str, set[str]]:
        with self.get_read_only_session() as session:
            query = (
                select(FileObjectEntry.virtual_file_paths, FileObjectEntry.uid)
                .join(fw_files_table, FileObjectEntry.uid == fw_files_table.c.file_uid)
                .filter(fw_files_table.c.root_uid == root_uid)
                .filter(FileObjectEntry.uid.not_in(blacklist))
                .join(AnalysisEntry, AnalysisEntry.uid == FileObjectEntry.uid)
                .filter(AnalysisEntry.plugin == 'file_type')
                .filter(AnalysisEntry.result['mime'] == type_coerce('text/plain', JSONB))
            )
            return self._transpose_vfp_dict(
                {uid: vfp_dict[root_uid] for vfp_dict, uid in session.execute(query) if root_uid in vfp_dict}
            )

    @staticmethod
    def _transpose_vfp_dict(list_dict: dict[str, list[str]]) -> dict[str, set[str]]:
        """transposes results from {uid: [vfps]} to {vfp: {uid}}"""
        transposed = {}
        for uid, path_list in list_dict.items():
            for vfp in path_list:
                transposed.setdefault(get_top_of_virtual_path(vfp), set()).add(uid)
        return transposed

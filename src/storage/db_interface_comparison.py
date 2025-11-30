from __future__ import annotations

import logging
from time import time

from sqlalchemy import func, select, type_coerce
from sqlalchemy.dialects.postgresql import JSONB

from helperFunctions.data_conversion import (
    convert_comparison_id_to_list,
    convert_uid_list_to_comparison_id,
    normalize_comparison_id,
)
from storage.db_interface_base import ReadWriteDbInterface
from storage.db_interface_common import DbInterfaceCommon
from storage.schema import AnalysisEntry, ComparisonEntry, FileObjectEntry, fw_files_table


class FactComparisonException(Exception):  # noqa: N818
    def get_message(self):
        if self.args:
            return self.args[0]
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
        logging.info(f'Comparison result added to db: {comparison_id}')

    def comparison_exists(self, comparison_id: str) -> bool:
        with self.get_read_only_session() as session:
            query = select(ComparisonEntry.comparison_id).filter(ComparisonEntry.comparison_id == comparison_id)
            return bool(session.execute(query).scalar())

    def objects_exist(self, comparison_id: str) -> bool:
        uid_list = convert_comparison_id_to_list(comparison_id)
        with self.get_read_only_session() as session:
            query = select(func.count(FileObjectEntry.uid)).filter(FileObjectEntry.uid.in_(uid_list))
            return session.execute(query).scalar() == len(uid_list)

    @staticmethod
    def _calculate_comp_id(comparison_result):
        uid_set = {uid for c_dict in comparison_result['general'].values() for uid in c_dict}
        return convert_uid_list_to_comparison_id(uid_set)

    def get_comparison_result(self, comparison_id: str) -> dict | None:
        comparison_id = normalize_comparison_id(comparison_id)
        if not self.comparison_exists(comparison_id):
            logging.debug(f'Comparison result not found in db: {comparison_id}')
            return None
        with self.get_read_only_session() as session:
            comparison_entry = session.get(ComparisonEntry, comparison_id)
            logging.debug(f'Got comparison result from db: {comparison_id}')
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

    def page_comparison_results(self, skip=0, limit=0) -> list[tuple[str, str, float]]:
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
            return analysis.result.get('ssdeep') if analysis is not None else None

    def get_entropy(self, uid: str) -> float:
        with self.get_read_only_session() as session:
            analysis: AnalysisEntry = session.get(AnalysisEntry, (uid, 'unpacker'))
            if analysis is None or 'entropy' not in analysis.result:
                return 0.0
            return analysis.result.get('entropy', 0.0)

    def get_exclusive_files(self, comparison_id: str, root_uid: str) -> list[str]:
        if comparison_id is None or root_uid is None:
            return []
        try:
            result = self.get_comparison_result(comparison_id)
            exclusive_files = result['plugins']['File_Coverage']['exclusive_files'][root_uid]
        except (KeyError, FactComparisonException):
            exclusive_files = []
        return exclusive_files

    def get_vfp_of_included_text_files(self, root_uid: str, blacklist: set[str]) -> dict[str, set[str]]:
        with self.get_read_only_session() as session:
            query = (
                select(FileObjectEntry.uid)
                .join(fw_files_table, FileObjectEntry.uid == fw_files_table.c.file_uid)
                .filter(fw_files_table.c.root_uid == root_uid)
                .filter(FileObjectEntry.uid.not_in(blacklist))
                .join(AnalysisEntry, AnalysisEntry.uid == FileObjectEntry.uid)
                .filter(AnalysisEntry.plugin == 'file_type')
                .filter(AnalysisEntry.result['mime'] == type_coerce('text/plain', JSONB))
            )
            uid_list = list(session.execute(query).scalars())
        vfp_data = self.get_vfps_for_uid_list(uid_list, root_uid=root_uid)
        return self._transpose_vfp_dict(vfp_data)

    @staticmethod
    def _transpose_vfp_dict(vfp_data: dict[str, dict[str, list[str]]]) -> dict[str, set[str]]:
        """
        Look for files with the same "virtual file path".
        input: {uid {parent_uid: [vfp]}} -> output: {vfp: [uid]}
        """
        result = {}
        for uid in vfp_data:
            vfp_dict = vfp_data.get(uid)
            for vfp_list in vfp_dict.values():
                for vfp in vfp_list:
                    result.setdefault(vfp, set()).add(uid)
        return result

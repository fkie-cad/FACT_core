from __future__ import annotations

import logging
from collections import Counter
from typing import Any, Callable, Iterator, List, Tuple, TYPE_CHECKING, ItemsView

from sqlalchemy import column, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import InstrumentedAttribute, aliased

from storage.db_interface_base import ReadOnlyDbInterface, ReadWriteDbInterface
from storage.schema import AnalysisEntry, FileObjectEntry, FirmwareEntry, StatsEntry

if TYPE_CHECKING:
    from helperFunctions.types import UID
    from sqlalchemy.sql import Select

Stats = List[Tuple[str, int]]
RelativeStats = List[Tuple[str, int, float]]  # stats with relative share as third element


class StatsUpdateDbInterface(ReadWriteDbInterface):
    """
    Statistic module backend interface
    """

    def update_statistic(self, identifier: str, content_dict: dict):
        logging.debug(f'Updating {identifier} statistics')
        try:
            with self.get_read_write_session() as session:
                entry: StatsEntry | None = session.get(StatsEntry, identifier)
                if entry is None:  # no old entry in DB -> create new one
                    entry = StatsEntry(name=identifier, data=content_dict)
                    session.add(entry)
                else:  # there was an entry -> update stats data
                    entry.data = content_dict
        except SQLAlchemyError:
            logging.error(f'Could not save stats entry in the DB:\n{content_dict}')

    def get_count(self, q_filter: dict | None = None, firmware: bool = False) -> int:
        return self._get_aggregate(FileObjectEntry.uid, func.count, q_filter, firmware) or 0

    def get_sum(self, field: InstrumentedAttribute, q_filter: dict | None = None, firmware: bool = False) -> int:
        sum_ = self._get_aggregate(field, func.sum, q_filter, firmware)
        return int(sum_) if sum_ is not None else 0  # func.sum returns a `Decimal` but we want an int

    def get_avg(self, field: InstrumentedAttribute, q_filter: dict | None = None, firmware: bool = False) -> float:
        average = self._get_aggregate(field, func.avg, q_filter, firmware)
        return 0.0 if average is None else float(average)  # func.avg returns a `Decimal` but we want a float

    def _get_aggregate(
        self,
        field: InstrumentedAttribute,
        aggregation_function: Callable,
        q_filter: dict | None = None,
        firmware: bool = False,
    ) -> Any:
        """
        :param field: The field that is aggregated (e.g. `FileObjectEntry.size`)
        :param aggregation_function: The aggregation function (e.g. `func.sum`)
        :param q_filter: Optional query filters (e.g. `{"device_class": "Router"}`)
        :param firmware: If `True`, Firmware entries are queried. Else, the included FileObject entries are queried.
        :return: The aggregation result. The result will be `None` if no matches were found.
        """
        with self.get_read_only_session() as session:
            query = select(aggregation_function(field))
            if firmware:
                query = query.join(FirmwareEntry, FileObjectEntry.uid == FirmwareEntry.uid)
            else:  # query all included files instead of firmware
                query = query.join(FirmwareEntry, FileObjectEntry.root_firmware.any(uid=FirmwareEntry.uid))
            if self._filter_is_not_empty(q_filter):
                query = query.filter_by(**q_filter)
            return session.execute(query).scalar()

    def get_fo_count(self) -> int:
        with self.get_read_only_session() as session:
            query = select(func.count(FileObjectEntry.uid))
            count = session.execute(query).scalar()
            return int(count) if count is not None else 0

    def get_cumulated_fo_size(self) -> int:
        with self.get_read_only_session() as session:
            query = select(func.sum(FileObjectEntry.size))
            sum_ = session.execute(query).scalar()
            return int(sum_) if sum_ is not None else 0

    def count_distinct_values(self, key: InstrumentedAttribute, q_filter=None) -> Stats:
        """
        Get a sorted list of tuples with all unique values of a column `key` and the count of occurrences.
        E.g. key=FileObjectEntry.file_name, result: [('some.other.file', 1), ('some.file', 2)]

        :param key: A table column
        :param q_filter: Additional query filter (e.g. `AnalysisEntry.plugin == 'file_type'`)
        :return: list of unique values with their count
        """
        with self.get_read_only_session() as session:
            query = select(key, func.count(key)).filter(key.isnot(None)).group_by(key)
            if self._filter_is_not_empty(q_filter):
                query = query.filter_by(**q_filter)
            return _sort_tuples(session.execute(query))

    def count_distinct_in_analysis(
        self, key: InstrumentedAttribute, plugin: str, firmware: bool = False, q_filter=None
    ) -> Stats:
        """
        Count distinct values in analysis results: Get a list of tuples with all unique values of a key `key`
        inside analysis results. Example: get all unique MIME types and their count from the file_type analysis.
        Results are sorted by count in ascending order.

        :param key: Some field inside an analysis result (e.g. AnalysisEntry.result['mime'])
        :param plugin: The plugin name (e.g. `file_type`)
        :param firmware: Boolean flag indicating if we are searching for file or firmware entries
        :param q_filter: Additional query filter (e.g. `FirmwareEntry.device_class == 'router'`)
        :return: A list of unique values with their count (e.g. `[('text/plain': 2), ('application/x-executable': 3)]`
        """
        with self.get_read_only_session() as session:
            query = (
                select(key, func.count(key))
                .filter(AnalysisEntry.plugin == plugin)
                .filter(key.isnot(None))
                .group_by(key)
            )
            query = self._join_fw_or_fo(query, firmware)
            if self._filter_is_not_empty(q_filter):
                query = query.filter_by(**q_filter)
            return _sort_tuples(session.execute(query))

    def count_distinct_values_in_array(self, key: InstrumentedAttribute, plugin: str, q_filter=None) -> Stats:
        """
        Get a list of tuples with all unique values of an array stored under `key` and the count of occurrences.

        :param key: `Table.column['array']`
        :param plugin: The name of the analysis plugin.
        :param q_filter: Optional query filter (e.g. `AnalysisEntry.plugin == 'file_type'`)
        :return: list of unique values with their count
        """
        with self.get_read_only_session() as session:
            # jsonb_array_elements() works somewhat like $unwind in MongoDB
            query = (
                select(func.jsonb_array_elements(key).label('array_elements'), func.count('array_elements'))
                .filter(AnalysisEntry.plugin == plugin)
                .group_by('array_elements')
            )
            if self._filter_is_not_empty(q_filter):
                query = self._join_fw_or_fo(query, is_firmware=False)
                query = query.filter_by(**q_filter)
            return _sort_tuples(session.execute(query))

    def count_values_in_summary(self, plugin: str, q_filter: dict | None = None, firmware: bool = False) -> Stats:
        """
        Get counts of all values from all summaries of plugin `plugin`.

        :param plugin: The analysis plugin name.
        :param q_filter: Optional query filter (e.g. `{'device_class': 'router'}`)
        :param firmware: If true query only entries of FW root objects. Otherwise, query included objects.
        """
        with self.get_read_only_session() as session:
            query = select(func.unnest(AnalysisEntry.summary)).filter(AnalysisEntry.plugin == plugin)
            query = self._join_fw_or_fo(query, firmware)
            if self._filter_is_not_empty(q_filter):
                query = query.filter_by(**q_filter)
            return count_occurrences(session.execute(query).scalars())

    def get_arch_stats(self, q_filter: dict | None = None) -> list[tuple[str, int, UID]]:
        """
        Get architecture stats per firmware. Returns tuples with arch, count, and root_uid.
        """
        with self.get_read_only_session() as session:
            # unnest (convert array column summary to individual rows) summary entries in a subquery
            subquery = (
                select(func.unnest(AnalysisEntry.summary).label('arch'), AnalysisEntry.uid)
                .filter(AnalysisEntry.plugin == 'cpu_architecture')
                .subquery()
            )
            arch_analysis = aliased(AnalysisEntry, subquery)
            query = (
                select(column('arch'), func.count('arch'), FirmwareEntry.uid)
                .select_from(arch_analysis)
                .join(FileObjectEntry, FileObjectEntry.uid == arch_analysis.uid)
                .join(FirmwareEntry, FileObjectEntry.root_firmware.any(uid=FirmwareEntry.uid))
                # group results by root FW so that we get results per FW
                .group_by('arch', FirmwareEntry.uid)
            )
            if self._filter_is_not_empty(q_filter):
                query = query.filter_by(**q_filter)
            return list(session.execute(query))

    def get_unpacking_file_types(self, summary_key: str, q_filter: dict | None = None) -> Stats:
        with self.get_read_only_session() as session:
            unpacker_analysis = aliased(AnalysisEntry)
            key = AnalysisEntry.result['mime']
            query = (
                select(key, func.count(key))
                .select_from(unpacker_analysis)
                .join(AnalysisEntry, AnalysisEntry.uid == unpacker_analysis.uid)
                .filter(AnalysisEntry.plugin == 'file_type')
                .filter(unpacker_analysis.plugin == 'unpacker')
                .filter(unpacker_analysis.summary.any(summary_key))
                .group_by(key)
            )
            if self._filter_is_not_empty(q_filter):
                query = self._join_all(query)
                query = query.filter_by(**q_filter)
            return _sort_tuples(session.execute(query))

    def get_unpacking_entropy(self, summary_key: str, q_filter: dict | None = None) -> float:
        with self.get_read_only_session() as session:
            query = (
                select(AnalysisEntry.result['entropy'])
                .filter(AnalysisEntry.plugin == 'unpacker')
                .filter(AnalysisEntry.summary.any(summary_key))
            )
            if self._filter_is_not_empty(q_filter):
                query = self._join_all(query)
                query = query.filter_by(**q_filter)
            return _avg([float(entropy) for entropy in session.execute(query).scalars()])

    def get_used_unpackers(self, q_filter: dict | None = None) -> Stats:
        with self.get_read_only_session() as session:
            query = select(
                AnalysisEntry.result['plugin_used'], AnalysisEntry.result['number_of_unpacked_files']
            ).filter(AnalysisEntry.plugin == 'unpacker')
            if self._filter_is_not_empty(q_filter):
                query = self._join_all(query)
                query = query.filter_by(**q_filter)
            return count_occurrences([plugin for plugin, count in session.execute(query) if int(count) > 0])

    def get_regex_mime_match_count(self, regex: str, q_filter: dict | None = None) -> int:
        with self.get_read_only_session() as session:
            query = (
                select(func.count(AnalysisEntry.uid))
                .filter(AnalysisEntry.plugin == 'file_type')
                .filter(AnalysisEntry.result['full'].astext.regexp_match(regex))
            )
            if self._filter_is_not_empty(q_filter):
                query = self._join_fw_or_fo(query, is_firmware=False)
                query = query.filter_by(**q_filter)
            return session.execute(query).scalar()

    def get_release_date_stats(self, q_filter: dict | None = None) -> list[tuple[int, int, int]]:
        with self.get_read_only_session() as session:
            query = select(
                func.date_part('year', FirmwareEntry.release_date).label('year'),
                func.date_part('month', FirmwareEntry.release_date).label('month'),
                func.count(FirmwareEntry.uid),
            ).group_by('year', 'month')
            if self._filter_is_not_empty(q_filter):
                query = query.filter_by(**q_filter)
            return [(int(year), int(month), count) for year, month, count in session.execute(query)]

    def get_software_components(self, q_filter: dict | None = None) -> Stats:
        with self.get_read_only_session() as session:
            subquery = (
                select(func.jsonb_object_keys(AnalysisEntry.result).label('software'), AnalysisEntry.uid)
                .filter(AnalysisEntry.plugin == 'software_components')
                .subquery('subquery')
            )
            query = (
                select(subquery.c.software, func.count(subquery.c.software))
                .filter(subquery.c.software.notin_(['system_version', 'skipped']))
                .group_by(subquery.c.software)
            )
            if self._filter_is_not_empty(q_filter):
                query = query.join(FileObjectEntry, FileObjectEntry.uid == subquery.c.uid)
                query = query.join(FirmwareEntry, FileObjectEntry.root_firmware.any(uid=FirmwareEntry.uid))
                query = query.filter_by(**q_filter)
            return _sort_tuples(session.execute(query))

    @staticmethod
    def _join_fw_or_fo(query: Select, is_firmware: bool) -> Select:
        if is_firmware:  # query only root objects of firmware
            query = query.join(FirmwareEntry, FirmwareEntry.uid == AnalysisEntry.uid)
        else:  # query objects unpacked from firmware -> join on root_fw
            query = query.join(FileObjectEntry, FileObjectEntry.uid == AnalysisEntry.uid)
            query = query.join(FirmwareEntry, FileObjectEntry.root_firmware.any(uid=FirmwareEntry.uid))
        return query

    @staticmethod
    def _join_all(query):
        # join all FOs (root fw objects and included objects)
        query = query.join(FileObjectEntry, AnalysisEntry.uid == FileObjectEntry.uid)
        return query.join(
            FirmwareEntry,
            # is included FO | is root FO
            (FileObjectEntry.root_firmware.any(uid=FirmwareEntry.uid)) | (FileObjectEntry.uid == FirmwareEntry.uid),
        )

    @staticmethod
    def _filter_is_not_empty(query_filter: dict | None) -> bool:
        return query_filter is not None and query_filter != {}


def count_occurrences(result_list: list[str]) -> Stats:
    return _sort_tuples(Counter(result_list).items())


def _sort_tuples(query_result: ItemsView[str, int]) -> Stats:
    # Sort stats tuples by count in ascending order
    return sorted(_convert_to_tuples(query_result), key=lambda e: (e[1], e[0]))


def _convert_to_tuples(query_result: ItemsView[str, int]) -> Iterator[tuple[str, int]]:
    # results from the DB query will be of type `Row` and not actual tuples -> convert
    # (otherwise they cannot be serialized as JSON and not be saved in the stats DB)
    return (tuple(item) if not isinstance(item, tuple) else item for item in query_result)


def _avg(values: list[float]) -> float:
    if len(values) == 0:
        return 0
    return sum(values) / len(values)


class StatsDbViewer(ReadOnlyDbInterface):
    """
    Statistic module frontend interface
    """

    def get_statistic(self, identifier) -> dict | None:
        with self.get_read_only_session() as session:
            entry: StatsEntry | None = session.get(StatsEntry, identifier)
            if entry is None:
                return None
            return self._stats_entry_to_dict(entry)

    def get_stats_list(self, *identifiers: str) -> list[dict]:
        with self.get_read_only_session() as session:
            query = select(StatsEntry).filter(StatsEntry.name.in_(identifiers))
            return [self._stats_entry_to_dict(e) for e in session.execute(query).scalars()]

    @staticmethod
    def _stats_entry_to_dict(entry: StatsEntry) -> dict:
        return {
            '_id': entry.name,  # FixMe? for backwards compatibility -- change to new format?
            **entry.data,
        }

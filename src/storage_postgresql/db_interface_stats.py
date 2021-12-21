import logging
from typing import Any, Callable, List, Optional, Union

from sqlalchemy import func, select
from sqlalchemy.orm import InstrumentedAttribute

from storage_postgresql.db_interface_common import DbInterface, ReadWriteDbInterface
from storage_postgresql.schema import FileObjectEntry, FirmwareEntry, StatsEntry

Number = Union[float, int]


class StatsUpdateDbInterface(ReadWriteDbInterface):
    """
    Statistic module backend interface
    """

    def update_statistic(self, identifier: str, content_dict: dict):
        logging.debug(f'Updating {identifier} statistics')
        with self.get_read_write_session() as session:
            entry: StatsEntry = session.get(StatsEntry, identifier)
            if entry is None:  # no old entry in DB -> create new one
                entry = StatsEntry(name=identifier, data=content_dict)
                session.add(entry)
            else:  # there was an entry -> update stats data
                entry.data = content_dict

    def get_count(self, field: InstrumentedAttribute, filter_: Optional[dict] = None, firmware: bool = False) -> Number:
        return self._get_aggregate(field, func.count, filter_, firmware) or 0

    def get_sum(self, field: InstrumentedAttribute, filter_: Optional[dict] = None, firmware: bool = False) -> Number:
        return self._get_aggregate(field, func.sum, filter_, firmware) or 0

    def get_avg(self, field: InstrumentedAttribute, filter_: Optional[dict] = None, firmware: bool = False) -> float:
        return self._get_aggregate(field, func.avg, filter_, firmware) or 0.0

    def _get_aggregate(
        self,
        field: InstrumentedAttribute,
        aggregation_function: Callable,
        query_filter: Optional[dict] = None,
        firmware: bool = False
    ) -> Any:
        """
        :param field: The field that is aggregated (e.g. `FileObjectEntry.size`)
        :param aggregation_function: The aggregation function (e.g. `func.sum`)
        :param query_filter: Optional filters (e.g. `{"device_class": "Router"}`)
        :param firmware: If `True`, Firmware entries are queried. Else, the included FileObject entries are queried.
        :return: The aggregation result. The result will be `None` if no matches were found.
        """
        with self.get_read_only_session() as session:
            query = select(aggregation_function(field))
            if firmware:
                query = query.join(FirmwareEntry, FileObjectEntry.uid == FirmwareEntry.uid)
            else:  # query all included files instead of firmware
                query = query.join(FirmwareEntry, FileObjectEntry.root_firmware.any(uid=FirmwareEntry.uid))
            if query_filter:
                query = query.filter_by(**query_filter)
            return session.execute(query).scalar()


class StatsDbViewer(DbInterface):
    """
    Statistic module frontend interface
    """

    def get_statistic(self, identifier) -> Optional[dict]:
        with self.get_read_only_session() as session:
            entry: StatsEntry = session.get(StatsEntry, identifier)
            if entry is None:
                return None
            return self._stats_entry_to_dict(entry)

    def get_stats_list(self, *identifiers: str) -> List[dict]:
        with self.get_read_only_session() as session:
            query = select(StatsEntry).filter(StatsEntry.name.in_(identifiers))
            return [self._stats_entry_to_dict(e) for e in session.execute(query).scalars()]

    @staticmethod
    def _stats_entry_to_dict(entry: StatsEntry) -> dict:
        return {
            '_id': entry.name,  # FixMe? for backwards compatibility -- change to new format?
            **entry.data,
        }

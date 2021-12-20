import logging
from typing import Any, Callable, List, Optional, Union

from sqlalchemy import func, select
from sqlalchemy.orm import InstrumentedAttribute

from storage_postgresql.db_interface_common import DbInterface, ReadWriteDbInterface
from storage_postgresql.schema import StatsEntry


class StatsDbUpdater(ReadWriteDbInterface):
    '''
    Statistic module backend interface
    '''

    def update_statistic(self, identifier: str, content_dict: dict):
        logging.debug(f'Updating {identifier} statistics')
        with self.get_read_write_session() as session:
            entry: StatsEntry = session.get(StatsEntry, identifier)
            if entry is None:  # no old entry in DB -> create new one
                entry = StatsEntry(name=identifier, data=content_dict)
                session.add(entry)
            else:  # there was an entry -> update stats data
                entry.data = content_dict

    def get_sum(self, field: InstrumentedAttribute, filter_: Optional[dict] = None) -> Union[float, int]:
        return self._get_aggregate(field, filter_, func.sum)

    def get_avg(self, field: InstrumentedAttribute, filter_: Optional[dict] = None) -> float:
        return self._get_aggregate(field, filter_, func.avg)

    def _get_aggregate(self, field: InstrumentedAttribute, filter_: Optional[dict], function: Callable) -> Any:
        with self.get_read_only_session() as session:
            query = select(function(field))
            if filter_:
                query = query.filter_by(**filter_)
            return session.execute(query).scalar()


class StatsDbViewer(DbInterface):
    '''
    Statistic module frontend interface
    '''

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

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from storage.db_interface_stats import Stats


def build_stats_entry_from_date_query(release_date_stats: list[tuple[int, int, int]]) -> Stats:
    time_dict = _build_time_dict(release_date_stats)
    return [
        (f'{_get_month_name(month)} {year}', count)
        for year in sorted(time_dict)
        for month, count in sorted(time_dict[year].items())
    ]


def _build_time_dict(release_date_stats: list[tuple[int, int, int]]) -> dict[int, dict[int, int]]:
    result = {}
    for year, month, count in release_date_stats:
        if year > 1970:  # noqa: PLR2004
            result.setdefault(year, {})[month] = count
    if result:
        _fill_in_time_gaps(result)
    return result


def _fill_in_time_gaps(time_dict: dict[int, dict[int, int]]):
    if time_dict == {}:
        return
    start_year = min(time_dict)
    start_month = min(time_dict[start_year])
    end_year = max(time_dict)
    end_month = max(time_dict[end_year])
    for year in range(start_year, end_year + 1):
        time_dict.setdefault(year, {})
        min_month = start_month if year == start_year else 1
        max_month = end_month if year == end_year else 12
        for month in range(min_month, max_month + 1):
            time_dict[year].setdefault(month, 0)


def _get_month_name(month_int):
    return datetime(1900, month_int, 1).strftime('%B')

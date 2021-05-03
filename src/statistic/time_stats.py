from datetime import datetime


def build_stats_entry_from_date_query(date_query):
    time_dict = _build_time_dict(date_query)
    result = []
    for year in sorted(time_dict.keys()):
        for month in sorted(time_dict[year].keys()):
            result.append(('{} {}'.format(_get_month_name(month), year), time_dict[year][month]))
    return result


def _build_time_dict(query):
    result = {}
    for item in query:
        year = item['_id']['year']
        month = item['_id']['month']
        count = item['count']
        if year > 1970:
            if year not in result:
                result[year] = {}
            result[year][month] = count
    _fill_in_time_gaps(result)
    return result


def _fill_in_time_gaps(time_dict):
    if time_dict:
        start_year = min(time_dict.keys())
        start_month = min(time_dict[start_year].keys())
        end_year = max(time_dict.keys())
        end_month = max(time_dict[end_year].keys())
        for year in range(start_year, end_year + 1):
            if year not in time_dict:
                time_dict[year] = {}
            min_month = start_month if year == start_year else 1
            max_month = end_month if year == end_year else 12
            for month in range(min_month, max_month + 1):
                if month not in time_dict[year]:
                    time_dict[year][month] = 0


def _get_month_name(month_int):
    return datetime(1900, month_int, 1).strftime('%B')

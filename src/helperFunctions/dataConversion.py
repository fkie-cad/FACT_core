from datetime import datetime
from itertools import combinations
from pickle import dumps
from typing import KT, VT, Dict, Iterable, List, Optional, Set


def make_bytes(code):
    if isinstance(code, bytes):
        return code
    if isinstance(code, str):
        return code.encode('utf-8')
    return bytes(code)


def make_unicode_string(code):
    if isinstance(code, str):
        return code.encode(errors='replace').decode()
    if isinstance(code, bytes):
        return code.decode(errors='replace')
    return code.__str__()


def make_list_from_dict(dict_object):
    return list(dict_object.values())


def get_dict_size(dict_object):
    return len(dumps(dict_object))


def list_of_lists_to_list_of_sets(list_of_lists):
    tmp = []
    for item in list_of_lists:
        tmp.append(set(item))
    return tmp


def list_of_sets_to_list_of_lists(list_of_sets: List[Set]) -> List[List]:
    if not list_of_sets:
        return []
    return [sorted(item) for item in list_of_sets]


def convert_uid_list_to_compare_id(uid_list: Iterable[str]) -> str:
    return ';'.join(sorted(uid_list))


def convert_compare_id_to_list(compare_id: str) -> List[str]:
    return compare_id.split(';')


def normalize_compare_id(compare_id: str) -> str:
    uids = convert_compare_id_to_list(compare_id)
    return convert_uid_list_to_compare_id(uids)


def get_value_of_first_key(input_dict: Dict[KT, VT]) -> Optional[VT]:
    return input_dict[sorted(input_dict.keys())[0]] if input_dict else None


def none_to_none(input_data):
    if input_data == 'None':
        input_data = None
    return input_data


def remove_subsets_from_list_of_sets(list_of_sets: List[set]):
    sets_to_delete = []
    for set1, set2 in combinations(list_of_sets, 2):
        if set1.issubset(set2):
            sets_to_delete.append(set1)
        elif set2.issubset(set1):
            sets_to_delete.append(set2)
    for subset in sets_to_delete:
        if subset in list_of_sets:
            list_of_sets.remove(subset)


def convert_str_to_time(string):
    '''
    firmware release dates are entered in the form 'YYYY-MM-DD' and need to be converted to MongoDB date objects
    in order to be stored in the database
    :param string: date string of the form 'YYYY-MM-DD'
    :return: datetime object (compatible with pymongo)
    '''
    try:
        return datetime.strptime(string, '%Y-%m-%d')
    except ValueError:
        return datetime.fromtimestamp(0)


def convert_time_to_str(time_obj):
    if isinstance(time_obj, datetime):
        return time_obj.strftime('%Y-%m-%d')
    if isinstance(time_obj, str):
        return time_obj
    return '1970-01-01'


def build_time_dict(query):
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

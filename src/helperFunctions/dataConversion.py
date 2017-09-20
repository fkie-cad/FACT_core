import json
import re
from datetime import datetime
from pickle import dumps


def make_bytes(code):
    if isinstance(code, bytes):
        return code
    elif isinstance(code, str):
        return code.encode('utf-8')
    else:
        return bytes(code)


def make_unicode_string(code):
    if isinstance(code, str):
        return code.encode(errors='replace').decode()
    elif isinstance(code, bytes):
        try:
            tmp = code.decode('utf-8')
        except:
            try:
                tmp = code.decode('iso-8859-1')
            except:
                tmp = code.decode('utf-8', 'replace')
        return tmp
    else:
        return code.__str__()


def make_dict_from_list(list_object):
    d = {}
    for i in range(len(list_object)):
        d['{}'.format(i)] = list_object[i]
    return d


def make_list_from_dict(dict_object):
    l = []
    for item in dict_object.keys():
        l.append(dict_object[item])
    return l


def printable_dictionary(dict_object):
    return json.dumps(dict_object, indent=4)


def dict_size(dict_object):
    pobj = dumps(dict_object)
    return len(pobj)


def list_of_lists_to_list_of_sets(list_of_lists):
    tmp = []
    for item in list_of_lists:
        tmp.append(set(item))
    return tmp


def list_of_sets_to_list_of_lists(list_of_sets):
    tmp = []
    if not list_of_sets:
        return []
    for item in list_of_sets:
        tmp_item = list(item)
        tmp_item.sort()
        tmp.append(tmp_item)
    return tmp


def list_to_unified_string_list(uids):
    uids.sort()
    return ';'.join(uids)


def string_list_to_list(string_list):
    return string_list.split(';')


def unify_string_list(string_list):
        uids = string_list.split(';')
        return list_to_unified_string_list(uids)


def get_value_of_first_key(input_dict):
    key_list = list(input_dict.keys())
    key_list.sort()
    if len(key_list) > 0:
        return input_dict[key_list[0]]
    else:
        return None


def none_to_none(input_data):
    if input_data == 'None':
        input_data = None
    return input_data


def remove_included_sets_from_list_of_sets(list_of_sets):
    sets_to_delete = []
    for subset in list_of_sets:
        for superset in list_of_sets:
            if subset.issubset(superset) and not subset == superset:
                sets_to_delete.append(subset)
    for subset in sets_to_delete:
        if subset in list_of_sets:
            list_of_sets.remove(subset)


def remove_uneccessary_spaces(input_string):
    tmp = input_string.split()
    tmp = ' '.join(tmp)
    return tmp


def convert_str_to_time(s):
    '''
    firmware release dates are entered in the form 'YYYY-MM-DD' and need to be converted to MongoDB date objects
    in order to be stored in the database
    :param s: date string of the form 'YYYY-MM-DD'
    :return: datetime object (compatible with pymongo)
    '''
    try:
        return datetime.strptime(s, '%Y-%m-%d')
    except ValueError:
        return datetime.fromtimestamp(0)


def convert_time_to_str(time_obj):
    if type(time_obj) == datetime:
        return time_obj.strftime('%Y-%m-%d')
    elif type(time_obj) == str:
        return time_obj
    else:
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
    if not len(time_dict) == 0:
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


def remove_linebreaks_from_byte_string(byte_string):
    '''
    Removes \x0A und \x0D line breaks from a byte string and returns sanitized string and number of removed breaks
    :param byte_string: Any byte string
    :return: sanitized_byte_string, number_of_removed_linebreaks
    '''
    rep = {b'\x0a': b'', b'\x0d': b''}  # CR LF
    rep = dict((re.escape(k), v) for k, v in rep.items())
    pattern = re.compile(b'|'.join(rep.keys()))
    return pattern.subn(lambda m: rep[re.escape(m.group(0))], byte_string)

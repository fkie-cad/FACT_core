'''
Jinja2 template filter
'''
import logging
import re
import sys
from base64 import standard_b64encode
from operator import itemgetter
from time import localtime, strftime, struct_time

from common_helper_files import human_readable_file_size

from helperFunctions.dataConversion import make_unicode_string
from helperFunctions.web_interface import get_color_list


def generic_nice_representation(i):
    if isinstance(i, struct_time):
        return strftime('%Y-%m-%d - %H:%M:%S', i)
    elif isinstance(i, list):
        return nice_list(i)
    elif isinstance(i, dict):
        return nice_dict(i)
    elif isinstance(i, float) or isinstance(i, int):
        return nice_number_filter(i)
    elif isinstance(i, str):
        return replace_underscore_filter(i)
    elif isinstance(i, bytes):
        return bytes_to_str_filter(i)
    else:
        return i


def nice_number_filter(i):
    if isinstance(i, int):
        return '{:,}'.format(i)
    elif isinstance(i, float):
        return '{:,.2f}'.format(i)
    elif i is None:
        return 'not available'
    else:
        return i


def byte_number_filter(i, verbose=False):
    if isinstance(i, int) or isinstance(i, float):
        if verbose:
            return '{} ({})'.format(human_readable_file_size(i), format(i, ',d') + ' bytes')
        else:
            return human_readable_file_size(i)
    else:
        return 'not available'


def encode_base64_filter(s):
    return standard_b64encode(s).decode('utf-8')


def bytes_to_str_filter(s):
    return make_unicode_string(s)


def replace_underscore_filter(s):
    return s.replace('_', ' ')


def nice_list(input_data):
    input_data = _get_sorted_list(input_data)
    if isinstance(input_data, list):
        tmp = '<ul>\n'
        for item in input_data:
            tmp += '\t<li>{}</li>\n'.format(_handle_generic_data(item))
        tmp += '</ul>\n'
        return tmp
    else:
        return input_data


def _handle_generic_data(input_data):
    if isinstance(input_data, dict):
        return nice_dict(input_data)
    else:
        return input_data


def nice_dict(input_data):
    if isinstance(input_data, dict):
        tmp = ''
        key_list = list(input_data.keys())
        key_list.sort()
        for item in key_list:
            tmp += '{}: {}<br />'.format(item, input_data[item])
        return tmp
    else:
        return input_data


def list_to_line_break_string(input_data):
    input_data = _get_sorted_list(input_data)
    return list_to_line_break_string_no_sort(input_data)


def list_to_line_break_string_no_sort(input_data):
    if isinstance(input_data, list):
        return '\n'.join(input_data) + '\n'
    else:
        return input_data


def uids_to_link(input_data, root_uid=None):
    tmp = input_data.__str__()
    uid_list = get_all_uids_in_string(tmp)
    for match in uid_list:
        tmp = tmp.replace(
            match, '<a href="/analysis/{}/ro/{}">{}</a>'.format(match, root_uid, match))
    return tmp


def get_all_uids_in_string(s):
    result = re.findall(r'[a-f0-9]{64}_[0-9]+', s)
    result = list(set(result))
    result.sort()
    return result


def _get_sorted_list(input_data):
    '''
    returns a sorted list if input data is a set or list
    returns input_data unchanged if it is whether a list nor a set
    '''
    if isinstance(input_data, set):
        input_data = list(input_data)
    if isinstance(input_data, list):
        try:
            input_data.sort()
        except Exception as e:
            logging.warning(
                'could not sort list: {} - {}'.format(sys.exc_info()[0].__name__, e))
    return input_data


def nice_unix_time(unix_time_stamp):
    '''
    input unix_time_stamp
    output string 'YYYY-MM-DD HH:MM:SS'
    '''
    if isinstance(unix_time_stamp, float) or isinstance(unix_time_stamp, int):
        tmp = localtime(unix_time_stamp)
        return strftime('%Y-%m-%d %H:%M:%S', tmp)
    else:
        return unix_time_stamp


def infection_color(input_data):
    '''
    sets color to green if zero or clean
    else sets color to red
    '''
    return text_highlighter(input_data, green=['clean', 0], red=['*'])


def text_highlighter(input_data, green=['clean', 'online', 0], red=['offline']):
    '''
    sets color to green if input found in green
    sets color to red if input found in red
    else do not set color
    special character * for all inputs available
    '''
    if input_data in green:
        return '<span style="color:green;">{}</span>'.format(input_data)
    elif input_data in red:
        return '<span style="color:red;">{}</span>'.format(input_data)
    elif '*' in green:
        return '<span style="color:green;">{}</span>'.format(input_data)
    elif '*' in red:
        return '<span style="color:red;">{}</span>'.format(input_data)
    else:
        return input_data


def get_first_value(data):
    return data[0]


def get_second_value(data):
    return data[1]


def sort_chart_list_by_name(input_data):
    try:
        input_data.sort(key=get_first_value)
    except Exception as e:
        logging.error(
            'could not sort chart list {}: {} - {}'.format(input_data, sys.exc_info()[0].__name__, e))
        return []
    else:
        return input_data


def sort_chart_list_by_value(input_data):
    try:
        input_data.sort(key=get_second_value, reverse=True)
    except Exception as e:
        logging.error(
            'could not sort chart list {}: {} - {}'.format(input_data, sys.exc_info()[0].__name__, e))
        return []
    else:
        return input_data


def sort_comments(comment_list):
    try:
        comment_list.sort(key=itemgetter('time'), reverse=True)
    except Exception as e:
        logging.error('could not sort comment list {}: {} - {}'.format(
            comment_list, sys.exc_info()[0].__name__, e))
        return []
    else:
        return comment_list


def data_to_chart_limited(data, limit=10, color_list=None):
    try:
        label_list, value_list = map(list, zip(*data))
    except ValueError:
        return None
    label_list, value_list = set_limit_for_data_to_chart(label_list, limit, value_list)
    color_list = set_color_list_for_data_to_chart(color_list, value_list)
    result = {
        'labels': label_list,
        'datasets': [{
            'data': value_list,
            'backgroundColor': color_list,
            'borderColor': color_list,
            'borderWidth': 1
        }]
    }
    return result


def data_to_chart_with_value_percentage_pairs(data, limit=10, color_list=None):
    try:
        label_list, value_list, percentage_list = map(list, zip(*data))
    except ValueError:
        return None
    label_list, value_list = set_limit_for_data_to_chart(label_list, limit, value_list)
    color_list = set_color_list_for_data_to_chart(color_list, value_list)
    result = {
        "labels": label_list,
        "datasets": [{
            "data": value_list,
            "percentage": percentage_list,
            "backgroundColor": color_list,
            "borderColor": color_list,
            "borderWidth": 1
        }]
    }
    return result


def set_color_list_for_data_to_chart(color_list, value_list):
    if not color_list:
        color_list = get_color_list(len(value_list))
    return color_list


def set_limit_for_data_to_chart(label_list, limit, value_list):
    if limit and len(label_list) > limit:
        label_list = label_list[:limit]
        label_list.append("rest")
        rest_sum = sum(value_list[limit:])
        value_list = value_list[:limit]
        value_list.append(rest_sum)
    return label_list, value_list


def data_to_chart(data):
    color_list = get_color_list(1) * len(data)
    return data_to_chart_limited(data, limit=0, color_list=color_list)


def get_canvas_height(dataset, maximum=11, bar_heigth=5):
    return min(len(dataset), maximum) * bar_heigth + 4


def comment_out_regex_meta_chars(input_data):
    '''
    comments out chars used by regular expressions in the input string
    '''
    meta_chars = ['^', '$', '.', '[', ']',
                  '|', '(', ')', '?', '*', '+', '{', '}']
    for c in meta_chars:
        if c in input_data:
            input_data = input_data.replace(c, '\\{}'.format(c))
    return input_data


def render_tags(tag_dict, additional_class='', size=10):
    output = ''
    if tag_dict:
        for tag in sorted(tag_dict.keys()):
            output += '<span class="label label-pill label-{} {}" style="font-size: {}px;">{}</span>\n'.format(
                tag_dict[tag], additional_class, size, tag)
    return output


def fix_cwe(s):
    if ("CWE" in s):
        return s.split("]")[0].split("E")[-1]
    else:
        logging.warning("Expected a CWE string.")
        return ""


def vulnerability_class(score):
    if score == 'high':
        return 'alert'
    elif score == 'medium':
        return 'warning'
    elif score == 'low':
        return 'active'
    return None

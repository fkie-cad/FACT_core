import logging
import random
import re
import zlib
from base64 import standard_b64encode
from operator import itemgetter
from string import ascii_letters
from time import localtime, strftime, struct_time
from typing import AnyStr, List, Optional

from common_helper_files import human_readable_file_size
from flask import render_template

from helperFunctions.compare_sets import remove_duplicates_from_list
from helperFunctions.dataConversion import make_unicode_string
from helperFunctions.tag import TagColor
from helperFunctions.web_interface import get_color_list
from web_interface.security.authentication import user_has_privilege
from web_interface.security.privileges import PRIVILEGES


def generic_nice_representation(i):  # pylint: disable=too-many-return-statements
    if isinstance(i, struct_time):
        return strftime('%Y-%m-%d - %H:%M:%S', i)
    if isinstance(i, list):
        return list_group(i)
    if isinstance(i, dict):
        return nice_dict(i)
    if isinstance(i, (float, int)):
        return nice_number_filter(i)
    if isinstance(i, str):
        return replace_underscore_filter(i)
    if isinstance(i, bytes):
        return bytes_to_str_filter(i)
    return i


def nice_number_filter(i):
    if isinstance(i, int):
        return '{:,}'.format(i)
    if isinstance(i, float):
        return '{:,.2f}'.format(i)
    if i is None:
        return 'not available'
    return i


def byte_number_filter(i, verbose=False):
    if not isinstance(i, (float, int)):
        return 'not available'
    if verbose:
        return '{} ({})'.format(human_readable_file_size(i), format(i, ',d') + ' bytes')
    return human_readable_file_size(i)


def encode_base64_filter(string):
    return standard_b64encode(string).decode('utf-8')


def bytes_to_str_filter(string):
    return make_unicode_string(string)


def replace_underscore_filter(string):
    return string.replace('_', ' ')


def list_group(input_data):
    input_data = _get_sorted_list(input_data)
    if isinstance(input_data, list):
        http_list = '<ul class="list-group list-group-flush">\n'
        for item in input_data:
            http_list += '\t<li class="list-group-item">{}</li>\n'.format(_handle_generic_data(item))
        http_list += '</ul>\n'
        return http_list
    return input_data


def list_group_collapse(input_data, btn_class=None):
    input_data = [_handle_generic_data(item) for item in _get_sorted_list(input_data)]
    if input_data:
        collapse_id = random_collapse_id()
        first_item = input_data.pop(0)
        return render_template(
            'generic_view/collapsed_list.html',
            first_item=first_item, collapse_id=collapse_id, input_data=input_data, btn_class=btn_class
        )
    return ''


def _handle_generic_data(input_data):
    if isinstance(input_data, dict):
        return nice_dict(input_data)
    return input_data


def nice_dict(input_data):
    if isinstance(input_data, dict):
        tmp = ''
        key_list = list(input_data.keys())
        key_list.sort()
        for item in key_list:
            tmp += '{}: {}<br />'.format(item, input_data[item])
        return tmp
    return input_data


def list_to_line_break_string(input_data):
    input_data = _get_sorted_list(input_data)
    return list_to_line_break_string_no_sort(input_data)


def list_to_line_break_string_no_sort(input_data):
    if isinstance(input_data, list):
        return '\n'.join(input_data) + '\n'
    return input_data


def uids_to_link(input_data, root_uid=None):
    tmp = str(input_data)
    uid_list = get_all_uids_in_string(tmp)
    for match in uid_list:
        tmp = tmp.replace(match, '<a href="/analysis/{0}/ro/{1}">{0}</a>'.format(match, root_uid))
    return tmp


def get_all_uids_in_string(string):
    result = re.findall(r'[a-f0-9]{64}_[0-9]+', string)
    result = remove_duplicates_from_list(result)
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
        except (AttributeError, TypeError):
            logging.warning('Could not sort list', exc_info=True)
    return input_data


def nice_unix_time(unix_time_stamp):
    '''
    input unix_time_stamp
    output string 'YYYY-MM-DD HH:MM:SS'
    '''
    if isinstance(unix_time_stamp, (float, int)):
        tmp = localtime(unix_time_stamp)
        return strftime('%Y-%m-%d %H:%M:%S', tmp)
    return unix_time_stamp


def infection_color(input_data):
    '''
    sets color to green if zero or clean
    else sets color to red
    '''
    return text_highlighter(input_data, green=['clean', 0], red=['*'])


def text_highlighter(input_data, green=None, red=None):
    '''
    sets color to green if input found in green
    sets color to red if input found in red
    else do not set color
    special character * for all inputs available
    '''
    if red is None:
        red = ['offline']
    if green is None:
        green = ['clean', 'online', 0]
    html = '<span style="color:{color};">{content}</span>'
    if input_data in green:
        return html.format(color='green', content=input_data)
    if input_data in red:
        return html.format(color='red', content=input_data)
    if '*' in green:
        return html.format(color='green', content=input_data)
    if '*' in red:
        return html.format(color='red', content=input_data)
    return input_data


def sort_chart_list_by_name(input_data):
    try:
        input_data.sort(key=lambda x: x[0])
    except (AttributeError, IndexError, KeyError, TypeError):
        logging.error('Could not sort chart list {}'.format(input_data), exc_info=True)
        return []
    return input_data


def sort_chart_list_by_value(input_data):
    try:
        input_data.sort(key=lambda x: x[1], reverse=True)
    except (AttributeError, IndexError, KeyError, TypeError):
        logging.error('Could not sort chart list {}'.format(input_data), exc_info=True)
        return []
    return input_data


def sort_comments(comment_list):
    try:
        comment_list.sort(key=itemgetter('time'), reverse=True)
    except (AttributeError, KeyError, TypeError):
        logging.error('Could not sort comment list {}'.format(comment_list), exc_info=True)
        return []
    return comment_list


def data_to_chart_limited(data, limit=10, color_list=None):
    try:
        label_list, value_list = [list(d) for d in zip(*data)]
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


def data_to_chart_with_value_percentage_pairs(data, limit=10, color_list=None):  # pylint: disable=invalid-name
    try:
        label_list, value_list, percentage_list = [list(d) for d in zip(*data)]
    except ValueError:
        return None
    label_list, value_list = set_limit_for_data_to_chart(label_list, limit, value_list)
    color_list = set_color_list_for_data_to_chart(color_list, value_list)
    result = {
        'labels': label_list,
        'datasets': [{
            'data': value_list,
            'percentage': percentage_list,
            'backgroundColor': color_list,
            'borderColor': color_list,
            'borderWidth': 1
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
        label_list.append('rest')
        rest_sum = sum(value_list[limit:])
        value_list = value_list[:limit]
        value_list.append(rest_sum)
    return label_list, value_list


def data_to_chart(data):
    color_list = get_color_list(1) * len(data)
    return data_to_chart_limited(data, limit=0, color_list=color_list)


def get_canvas_height(dataset, maximum=11, bar_height=5):
    return min(len(dataset), maximum) * bar_height + 4


def comment_out_regex_meta_chars(input_data):
    '''
    comments out chars used by regular expressions in the input string
    '''
    meta_chars = ['^', '$', '.', '[', ']', '|', '(', ')', '?', '*', '+', '{', '}']
    for char in meta_chars:
        if char in input_data:
            input_data = input_data.replace(char, '\\{}'.format(char))
    return input_data


def render_tags(tag_dict, additional_class='', size=14):
    output = ''
    if tag_dict:
        for tag in sorted(tag_dict.keys()):
            output += '<span class="badge badge-{} {}" style="font-size: {}px;">{}</span>\n'.format(
                _fix_color_class(tag_dict[tag]), additional_class, size, tag)
    return output


def render_analysis_tags(tags, size=14):
    output = ''
    if tags:
        for plugin_name in tags:
            for key, tag in tags[plugin_name].items():
                output += '<span class="badge badge-{}" style="font-size: {}px;" data-toggle="tooltip" title="{}: {}">{}</span>\n'.format(
                    _fix_color_class(tag['color']), size, replace_underscore_filter(plugin_name), replace_underscore_filter(key), tag['value']
                )
    return output


def _fix_color_class(tag_color_class):
    return tag_color_class if tag_color_class in TagColor.ALL else TagColor.BLUE


def fix_cwe(string):
    if 'CWE' in string:
        return string.split(']')[0].split('E')[-1]
    logging.warning('Expected a CWE string.')
    return ''


def vulnerability_class(score):
    if score == 'high':
        return 'danger'
    if score == 'medium':
        return 'warning'
    if score == 'low':
        return 'active'
    return None


def sort_users_by_name(user_list):
    return sorted(user_list, key=lambda u: u.email)


def user_has_role(current_user, role):
    return current_user.is_authenticated and user_has_privilege(current_user, role)


def sort_roles_by_number_of_privileges(roles, privileges=None):
    privileges = PRIVILEGES if privileges is None else privileges
    inverted_privileges = {}
    for key, value_list in privileges.items():
        for value in value_list:
            inverted_privileges.setdefault(value, []).append(key)
    return sorted(roles, key=lambda role: len(inverted_privileges[role]))


def filter_format_string_list_with_offset(offset_tuples):  # pylint: disable=invalid-name
    max_offset_len = len(str(max(list(zip(*offset_tuples))[0]))) if offset_tuples else 0
    lines = [
        '{0: >{width}}: {1}'.format(offset, repr(string)[1:-1], width=max_offset_len)
        for offset, string in sorted(offset_tuples)
    ]
    return '\n'.join(lines)


def decompress(string: AnyStr) -> str:
    if isinstance(string, bytes):
        try:
            return zlib.decompress(string).decode()
        except zlib.error:
            return string.decode()
    return string


def get_unique_keys_from_list_of_dicts(list_of_dicts: List[dict]):
    unique_keys = set()
    for dictionary in list_of_dicts:
        for key in dictionary:
            unique_keys.add(key)
    return unique_keys


def is_not_mandatory_analysis_entry(item: str, additional_entries: Optional[List[str]] = None) -> bool:
    return (
        item not in ['analysis_date', 'plugin_version', 'skipped', 'summary', 'system_version', 'tags']
        and (additional_entries is None or item not in additional_entries)
    )


def random_collapse_id():
    return ''.join((random.choice(ascii_letters) for _ in range(10)))


def create_firmware_version_links(firmware_list, selected_analysis=None):
    if selected_analysis:
        template = '<a href="/analysis/{{}}/{}">{{}}</a>'.format(selected_analysis)
    else:
        template = '<a href="/analysis/{}">{}</a>'

    return [template.format(firmware['_id'], firmware['version']) for firmware in firmware_list]

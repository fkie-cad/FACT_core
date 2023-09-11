from __future__ import annotations

import binascii
import stat

import semver
import json
import logging
import packaging.version
import random
import re
import zlib
from base64 import b64decode, standard_b64encode
from collections import defaultdict
from datetime import timedelta
from operator import itemgetter
from re import Match
from string import ascii_letters
from time import localtime, strftime, struct_time, time
from typing import Union

from common_helper_files import human_readable_file_size
from flask import render_template

from helperFunctions.compare_sets import remove_duplicates_from_list
from helperFunctions.data_conversion import make_unicode_string
from helperFunctions.tag import TagColor
from helperFunctions.web_interface import get_alternating_color_list
from web_interface.security.authentication import user_has_privilege
from web_interface.security.privileges import PRIVILEGES


def generic_nice_representation(i):  # noqa: PLR0911
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
        return f'{i:,}'
    if isinstance(i, float):
        return f'{i:,.2f}'
    if i is None:
        return 'not available'
    return i


def byte_number_filter(i, verbose=False):
    if not isinstance(i, (float, int)):
        return 'not available'
    if verbose:
        return f'{human_readable_file_size(i)} ({i:,d} bytes)'
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
            http_list += f'\t<li class="list-group-item">{_handle_generic_data(item)}</li>\n'
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
            first_item=first_item,
            collapse_id=collapse_id,
            input_data=input_data,
            btn_class=btn_class,
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
            tmp += f'{item}: {input_data[item]}<br />'
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
        tmp = tmp.replace(match, f'<a href="/analysis/{match}/ro/{root_uid}">{match}</a>')
    return tmp


def get_all_uids_in_string(string):
    result = re.findall(r'[a-f0-9]{64}_[0-9]+', string)
    result = remove_duplicates_from_list(result)
    result.sort()
    return result


def _get_sorted_list(input_data):
    """
    returns a sorted list if input data is a set or list
    returns input_data unchanged if it is whether a list nor a set
    """
    if isinstance(input_data, set):
        input_data = list(input_data)
    if isinstance(input_data, list):
        try:
            input_data.sort()
        except (AttributeError, TypeError):
            logging.warning('Could not sort list', exc_info=True)
    return input_data


def nice_unix_time(unix_time_stamp):
    """
    input unix_time_stamp
    output string 'YYYY-MM-DD HH:MM:SS'
    """
    if isinstance(unix_time_stamp, (float, int)):
        tmp = localtime(unix_time_stamp)
        return strftime('%Y-%m-%d %H:%M:%S', tmp)
    return unix_time_stamp


def infection_color(input_data):
    """
    sets color to green if zero or clean
    else sets color to red
    """
    return text_highlighter(input_data, green=['clean', 0], red=['*'])


def text_highlighter(input_data, green=None, red=None):
    """
    sets color to green if input found in green
    sets color to red if input found in red
    else do not set color
    special character * for all inputs available
    """
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
        logging.exception(f'Could not sort chart list {input_data}')
        return []
    return input_data


def sort_chart_list_by_value(input_data):
    try:
        input_data.sort(key=lambda x: x[1], reverse=True)
    except (AttributeError, IndexError, KeyError, TypeError):
        logging.exception(f'Could not sort chart list {input_data}')
        return []
    return input_data


def sort_comments(comment_list):
    try:
        comment_list.sort(key=itemgetter('time'), reverse=True)
    except (AttributeError, KeyError, TypeError):
        logging.exception(f'Could not sort comment list {comment_list}')
        return []
    return comment_list


def data_to_chart_with_value_percentage_pairs(data, limit=10):
    try:
        label_list, value_list, percentage_list, *links = (list(d) for d in zip(*data))
    except ValueError:
        return None
    label_list, value_list = set_limit_for_data_to_chart(label_list, limit, value_list)
    color_list = get_alternating_color_list(len(value_list), limit=limit)
    return {
        'labels': label_list,
        'datasets': [
            {
                'data': value_list,
                'percentage': percentage_list,
                'backgroundColor': color_list,
                'borderWidth': 0,
                'links': links[0] if links else 'null',
            }
        ],
    }


def set_limit_for_data_to_chart(label_list, limit, value_list):
    if limit and len(label_list) > limit:
        label_list = label_list[:limit]
        label_list.append('rest')
        rest_sum = sum(value_list[limit:])
        value_list = value_list[:limit]
        value_list.append(rest_sum)
    return label_list, value_list


def get_canvas_height(dataset, maximum=11, bar_height=5):
    return min(len(dataset), maximum) * bar_height + 4


def comment_out_regex_meta_chars(input_data):
    """
    comments out chars used by regular expressions in the input string
    """
    meta_chars = ['^', '$', '.', '[', ']', '|', '(', ')', '?', '*', '+', '{', '}']
    for char in meta_chars:
        if char in input_data:
            input_data = input_data.replace(char, f'\\{char}')
    return input_data


def render_fw_tags(tag_dict, size=14):
    output = ''
    if tag_dict:
        for tag, color in sorted(tag_dict.items()):
            output += render_template('generic_view/tags.html', color=color, value=tag, size=size)
    return output


def render_analysis_tags(tags, size=14):
    output = ''
    if tags:
        for plugin_name in tags:
            for key, tag in tags[plugin_name].items():
                if key == 'root_uid':
                    continue
                color = tag['color'] if tag['color'] in TagColor.ALL else TagColor.BLUE
                output += render_template(
                    'generic_view/tags.html',
                    color=color,
                    value=tag['value'],
                    tooltip=f'{plugin_name}: {key}',
                    size=size,
                )
    return output


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
    if score == 'none':
        return 'success'
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


def filter_format_string_list_with_offset(offset_tuples):
    max_offset_len = len(str(max(list(zip(*offset_tuples))[0]))) if offset_tuples else 0
    lines = [f'{offset: >{max_offset_len}}: {repr(string)[1:-1]}' for offset, string in sorted(offset_tuples)]
    return '\n'.join(lines)


def decompress(string: str) -> str:
    try:
        return zlib.decompress(b64decode(string)).decode()
    except (zlib.error, binascii.Error, TypeError):
        return string


def get_unique_keys_from_list_of_dicts(list_of_dicts: list[dict]):
    unique_keys = set()
    for dictionary in list_of_dicts:
        for key in dictionary:
            unique_keys.add(key)
    return unique_keys


def random_collapse_id():
    return ''.join(random.choice(ascii_letters) for _ in range(10))


def create_firmware_version_links(firmware_list, selected_analysis=None):
    if selected_analysis:
        template = f'<a href="/analysis/{{}}/{selected_analysis}">{{}}</a>'
    else:
        template = '<a href="/analysis/{}">{}</a>'

    return [template.format(uid, version) for uid, version in firmware_list]


def elapsed_time(start_time: float) -> int:
    return round(time() - start_time)


def format_duration(duration: float) -> str:
    return str(timedelta(seconds=duration))


def render_query_title(query_title: None | str | dict):
    if query_title is None:
        return None
    if isinstance(query_title, dict):
        return json.dumps(query_title, indent=2)
    return query_title


def replace_cve_with_link(string: str) -> str:
    return re.sub(r'CVE-\d+-\d+', _link_to_cve, string)


def _link_to_cve(match: Match) -> str:
    return f'<a href="https://nvd.nist.gov/vuln/detail/{match.group(0)}">{match.group(0)}</a>'


def replace_cwe_with_link(string: str) -> str:
    return re.sub(r'CWE-(\d+)', _link_to_cwe, string)


def _link_to_cwe(match: Match) -> str:
    return f'<a href="https://cwe.mitre.org/data/definitions/{match.group(1)}.html">{match.group(0)}</a>'


def sort_cve_results(cve_result: dict[str, dict[str, str]]) -> list[tuple[str, dict[str, str]]]:
    return sorted(cve_result.items(), key=_cve_sort_key)


def _cve_sort_key(item: tuple[str, dict[str, str]]) -> tuple[float, float, str]:
    """
    primary sorting key: -max(v2 score, v3 score)
    secondary sorting key: -min(v2 score, v3 score)
    tertiary sorting key: CVE ID
    use negative values so that highest scores come first, and we can also sort by CVE ID
    """
    v2_score, v3_score = (_cve_score_to_float(item[1].get(key, 0.0)) for key in ['score2', 'score3'])
    return -max(v2_score, v3_score), -min(v2_score, v3_score), item[0]


def _cve_score_to_float(score: float | str) -> float:
    try:
        return float(score)
    except ValueError:  # "N/A" entries
        return 0.0


def linter_reformat_issues(issues) -> dict[str, list[dict[str, str]]]:
    reformatted = defaultdict(list, {})
    for issue in issues:
        symbol = issue['symbol']
        content = {'line': issue['line'], 'column': issue['column'], 'message': issue['message']}
        reformatted[symbol].append(content)
    return reformatted


def hide_dts_binary_data(device_tree: str) -> str:
    # textual device tree data can contain huge chunks of binary data -> hide them from view if they are too large
    device_tree = re.sub(r'\[[0-9a-f ]{32,}]', '(BINARY DATA ...)', device_tree)
    return re.sub(r'<(0x[0-9a-f]+ ?){10,}>', '(BINARY DATA ...)', device_tree)


def get_searchable_crypto_block(crypto_material: str) -> str:
    """crypto material plugin results contain spaces and line breaks -> get a contiguous block without those"""
    blocks = crypto_material.replace(' ', '').split('\n')
    return sorted(blocks, key=len, reverse=True)[0]


def version_is_compatible(
    version: Union[str, semver.Version],
    other: Union[str, semver.Version],
    forgiving: bool = False,
) -> bool:
    """A warpper around ``semver.Version.is_compatible`` that allows non semver versions.
    If :paramref:`forgiving` is True non semver versions will try to be coerced to semver versions.
    If this does not succeed or :paramref:`forgiving` is False then any semver version will
    be considered incompatible to any other non semver version.
    So for example '1.1.0' would not be compatible '1.2' if forgiving is False.
    Otherwise it would be coerced from '1.2' to '1.2.0'.

    If both versions are not semver they are only compatible if they are equal.

    :param version: The version to check compatiblity for.
    :param other: The version to compare to.

    :return: If :paramref:`version` is compatible with :paramref:`other`.

    :raises ValueError: If both versions are neither semver nor ``packaging.version.Version`` versions.
    """
    version_is_semver = True
    try:
        if isinstance(version, str):
            version = semver.Version.parse(version)
    except ValueError:
        version_is_semver = forgiving
        version = _coerce_version(version)

    other_is_semver = True
    try:
        if isinstance(other, str):
            other = semver.Version.parse(other)
    except ValueError:
        other_is_semver = forgiving
        other = _coerce_version(other)

    if version_is_semver ^ other_is_semver:
        return False

    if not version_is_semver and not other_is_semver:
        try:
            return packaging.version.Version(version) == packaging.version.Version(other)
        except packaging.version.InvalidVersion as invalid_version:
            raise ValueError from invalid_version

    return version.is_compatible(other)


def _coerce_version(version: str) -> semver.Version:
    coerced = packaging.version.Version(version)
    return semver.Version(
        major=coerced.major,
        minor=coerced.minor,
        patch=coerced.micro,
        prerelease=coerced.pre,
        build=None,
    )


def as_ascii_table(data: dict) -> str:
    """Format a flat dictionary as two column ascii table"""
    return ''.join([f'{k:<10} {v!s:<10}\n' for k, v in data.items()])


def octal_to_readable(octal: str) -> str:
    return stat.filemode(int(octal, 8)).lstrip('?')

# -*- coding: utf-8 -*-

import json
import random

from common_helper_filter.time import time_format
from flask import render_template

from helperFunctions.dataConversion import none_to_none
from helperFunctions.uid import is_list_of_uids
from helperFunctions.web_interface import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.filter import byte_number_filter, encode_base64_filter, \
    bytes_to_str_filter, replace_underscore_filter, nice_list, data_to_chart_limited, data_to_chart, \
    uids_to_link, get_all_uids_in_string, list_to_line_break_string, sort_comments, \
    nice_unix_time, infection_color, nice_number_filter, sort_chart_list_by_name, sort_chart_list_by_value, \
    text_highlighter, get_canvas_height, comment_out_regex_meta_chars, \
    generic_nice_representation, list_to_line_break_string_no_sort, render_tags, data_to_chart_with_value_percentage_pairs


class FilterClass:
    '''
    This is WEB front end main class
    '''
    def __init__(self, app, program_version, config):
        self._program_version = program_version
        self._app = app
        self._config = config

        self._setup_filters()

    def _filter_print_program_version(self, *_):
        return '{}'.format(self._program_version)

    def _filter_replace_uid_with_file_name(self, input_data):
        tmp = input_data.__str__()
        uid_list = get_all_uids_in_string(tmp)
        for item in uid_list:
            with ConnectTo(FrontEndDbInterface, self._config) as sc:
                file_name = sc.get_file_name(item)
            tmp = tmp.replace('>{}<'.format(item), '>{}<'.format(file_name))
        return tmp

    def _filter_replace_uid_with_hid(self, input_data, root_uid=None):
        tmp = input_data.__str__()
        if tmp == 'None':
            return ' '
        uid_list = get_all_uids_in_string(tmp)
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            for item in uid_list:
                tmp = tmp.replace(item, sc.get_hid(item, root_uid=root_uid))
        return tmp

    def _filter_replace_uid_with_hid_link(self, input_data, root_uid=None):
        tmp = input_data.__str__()
        if tmp == 'None':
            return ' '
        uid_list = get_all_uids_in_string(tmp)
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            for item in uid_list:
                tmp = tmp.replace(item, '<a href="/analysis/{}/ro/{}">{}</a>'.format(item, root_uid, sc.get_hid(item, root_uid=root_uid)))
        return tmp

    def _filter_nice_uid_list(self, input_data, root_uid=None, selected_analysis=None):
        root_uid = none_to_none(root_uid)
        if not is_list_of_uids(input_data):
            return input_data
        show_id = str(random.randint(0, 999999))
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            included_files = sc.get_data_for_nice_list(input_data, root_uid)
        number_of_unanalyzed_files = len(input_data) - len(included_files)
        return render_template('generic_view/nice_fo_list.html', fo_list=included_files, u_show_id=show_id,
                               number_of_unanalyzed_files=number_of_unanalyzed_files,
                               root_uid=root_uid, selected_analysis=selected_analysis)

    def _filter_get_object_binary(self, uid):
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            binary = sc.get_binary_and_filename(uid)[0]
        return binary

    def _setup_filters(self):
        self._app.jinja_env.filters['print_program_version'] = self._filter_print_program_version
        self._app.jinja_env.filters['nice_generic'] = generic_nice_representation
        self._app.jinja_env.filters['number_format'] = byte_number_filter
        self._app.jinja_env.filters['nice_number'] = nice_number_filter
        self._app.jinja_env.filters['base64_encode'] = encode_base64_filter
        self._app.jinja_env.filters['bytes_to_str'] = bytes_to_str_filter
        self._app.jinja_env.filters['replace_underscore'] = replace_underscore_filter
        self._app.jinja_env.filters['nice_list'] = nice_list
        self._app.jinja_env.filters['nice_uid_list'] = self._filter_nice_uid_list
        self._app.jinja_env.filters['uids_to_link'] = uids_to_link
        self._app.jinja_env.filters['replace_uid_with_file_name'] = self._filter_replace_uid_with_file_name
        self._app.jinja_env.filters['replace_uid_with_hid'] = self._filter_replace_uid_with_hid
        self._app.jinja_env.filters['replace_uid_with_hid_link'] = self._filter_replace_uid_with_hid_link
        self._app.jinja_env.filters['list_to_line_break_string'] = list_to_line_break_string
        self._app.jinja_env.filters['list_to_line_break_string_no_sort'] = list_to_line_break_string_no_sort
        self._app.jinja_env.filters['nice_unix_time'] = nice_unix_time
        self._app.jinja_env.filters['infection_color'] = infection_color
        self._app.jinja_env.filters['get_object_binary'] = self._filter_get_object_binary
        self._app.jinja_env.filters['sort_chart_list_by_name'] = sort_chart_list_by_name
        self._app.jinja_env.filters['sort_chart_list_by_value'] = sort_chart_list_by_value
        self._app.jinja_env.filters['sort_comments'] = sort_comments
        self._app.jinja_env.filters['data_to_chart_limited'] = data_to_chart_limited
        self._app.jinja_env.filters['data_to_chart_with_value_percentage_pairs'] = data_to_chart_with_value_percentage_pairs
        self._app.jinja_env.filters['data_to_chart'] = data_to_chart
        self._app.jinja_env.filters['get_canvas_height'] = get_canvas_height
        self._app.jinja_env.filters['text_highlighter'] = text_highlighter
        self._app.jinja_env.filters['min'] = min
        self._app.jinja_env.filters['json_dumps'] = json.dumps
        self._app.jinja_env.filters['regex_meta'] = comment_out_regex_meta_chars
        self._app.jinja_env.filters['nice_time'] = time_format
        self._app.jinja_env.filters['render_tags'] = render_tags

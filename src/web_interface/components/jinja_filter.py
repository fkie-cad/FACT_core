from __future__ import annotations

import json
import logging

from common_helper_filter.time import time_format
from flask import render_template

import config
import web_interface.filter as flt
from helperFunctions.data_conversion import none_to_none
from helperFunctions.database import get_shared_session
from helperFunctions.hash import get_md5
from helperFunctions.uid import is_list_of_uids, is_uid
from helperFunctions.web_interface import cap_length_of_element, get_color_list
from web_interface.filter import elapsed_time, random_collapse_id
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from web_interface.frontend_database import FrontendDatabase
    from storage.db_interface_frontend import MetaEntry


class FilterClass:
    """
    This is WEB front end main class
    """

    def __init__(self, app, program_version, db: FrontendDatabase, **_):
        self._program_version = program_version
        self._app = app
        self.db = db

        self._setup_filters()

    def _filter_print_program_version(self, *_):
        return f'{self._program_version}'

    def _filter_replace_uid_with_file_name(self, input_data):
        tmp = input_data.__str__()
        uid_list = flt.get_all_uids_in_string(tmp)
        with get_shared_session(self.db.frontend) as frontend_db:
            for item in uid_list:
                file_name = frontend_db.get_file_name(item)
                tmp = tmp.replace(f'>{item}<', f'>{file_name}<')
        return tmp

    def _filter_replace_uid_with_hid(self, input_data, root_uid=None):
        tmp = str(input_data)
        if tmp == 'None':
            return ' '
        uid_list = flt.get_all_uids_in_string(tmp)
        for item in uid_list:
            tmp = tmp.replace(item, self.db.frontend.get_hid(item, root_uid=root_uid))
        return tmp

    def _filter_replace_comparison_uid_with_hid(self, input_data, root_uid=None):
        tmp = self._filter_replace_uid_with_hid(input_data, root_uid)
        res = tmp.split(';')
        return '  ||  '.join(res)

    def _filter_replace_uid_with_hid_link(self, input_data, root_uid=None):
        content = str(input_data)
        if content == 'None':
            return ' '
        uid_list = flt.get_all_uids_in_string(content)
        for uid in uid_list:
            hid = self.db.frontend.get_hid(uid, root_uid=root_uid)
            content = content.replace(uid, f'<a style="text-reset" href="/analysis/{uid}/ro/{root_uid}">{hid}</a>')
        return content

    def _filter_nice_uid_list(self, uids, root_uid=None, selected_analysis=None, filename_only=False):
        root_uid = none_to_none(root_uid)
        if not is_list_of_uids(uids):
            return uids

        analyzed_uids = self.db.frontend.get_data_for_nice_list(uids, root_uid)
        number_of_unanalyzed_files = len(uids) - len(analyzed_uids)
        first_item = analyzed_uids.pop(0)

        return render_template(
            'generic_view/nice_fo_list.html',
            fo_list=analyzed_uids,
            u_show_id=random_collapse_id(),
            number_of_unanalyzed_files=number_of_unanalyzed_files,
            root_uid=root_uid,
            selected_analysis=selected_analysis,
            first_item=first_item,
            filename_only=filename_only,
        )

    def _nice_virtual_path_list(self, virtual_path_list: list[list[str]], root_uid: str | None = None) -> list[str]:
        root_uid = none_to_none(root_uid)
        path_list = []
        all_uids = {uid for uid_list in virtual_path_list for uid in uid_list}
        hid_dict = self.db.frontend.get_hid_dict(all_uids, root_uid=root_uid)
        for uid_list in virtual_path_list:
            components = [self._virtual_path_element_to_span(hid_dict[uid], uid, root_uid=root_uid) for uid in uid_list]
            path_list.append(' '.join(components))
        return path_list

    @staticmethod
    def _virtual_path_element_to_span(hid_element: str, uid_element, root_uid) -> str:
        hid = cap_length_of_element(hid_element)
        if is_uid(uid_element):
            return (
                '<span class="badge badge-primary">'
                f'    <a style="color: #fff" href="/analysis/{uid_element}/ro/{root_uid}">'
                f'        {hid}'
                '    </a>'
                '</span>'
            )
        return f'<span class="badge badge-secondary">{hid}</span>'

    @staticmethod
    def _render_firmware_detail_tabular_field(firmware_meta_data):
        return render_template('generic_view/firmware_detail_tabular_field.html', firmware=firmware_meta_data)

    @staticmethod
    def _render_general_information_table(
        firmware: MetaEntry, root_uid: str, other_versions, selected_analysis, file_tree_paths
    ):
        return render_template(
            'generic_view/general_information.html',
            firmware=firmware,
            root_uid=root_uid,
            other_versions=other_versions,
            selected_analysis=selected_analysis,
            file_tree_paths=file_tree_paths,
        )

    @staticmethod
    def _split_user_and_password_type_entry(result: dict):
        new_result = {}
        for key, value in result.items():
            if ':' in key:
                *user_elements, password_type = key.split(':')
                user = ':'.join(user_elements)
            else:  # for backward compatibility
                user = key
                password_type = 'unix'
            new_result.setdefault(user, {})[password_type] = value
        return new_result

    def check_auth(self, _):
        return config.frontend.authentication.enabled

    def data_to_chart_limited(self, data, limit: int | None = None, color_list=None):
        limit = self._get_chart_element_count() if limit is None else limit
        try:
            label_list, value_list = (list(d) for d in zip(*data))
        except ValueError:
            return None
        label_list, value_list = flt.set_limit_for_data_to_chart(label_list, limit, value_list)
        color_list = get_color_list(len(value_list), limit=limit) if color_list is None else color_list
        return {
            'labels': label_list,
            'datasets': [{'data': value_list, 'backgroundColor': color_list, 'borderColor': '#fff', 'borderWidth': 2}],
        }

    def _get_chart_element_count(self):
        limit = config.frontend.max_elements_per_chart
        if limit > 100:  # noqa: PLR2004
            logging.warning('Value of "max_elements_per_chart" in configuration is too large.')
            return 100
        return limit

    def data_to_chart(self, data):
        color_list = get_color_list(1) * len(data)
        return self.data_to_chart_limited(data, limit=0, color_list=color_list)

    def _setup_filters(self):  # noqa: PLR0915
        self._app.jinja_env.add_extension('jinja2.ext.do')

        self._app.jinja_env.filters['all_items_equal'] = lambda data: len({str(value) for value in data.values()}) == 1
        self._app.jinja_env.filters['as_ascii_table'] = flt.as_ascii_table
        self._app.jinja_env.filters['auth_enabled'] = self.check_auth
        self._app.jinja_env.filters['base64_encode'] = flt.encode_base64_filter
        self._app.jinja_env.filters['bytes_to_str'] = flt.bytes_to_str_filter
        self._app.jinja_env.filters['data_to_chart'] = self.data_to_chart
        self._app.jinja_env.filters['data_to_chart_limited'] = self.data_to_chart_limited
        self._app.jinja_env.filters[
            'data_to_chart_with_value_percentage_pairs'
        ] = flt.data_to_chart_with_value_percentage_pairs
        self._app.jinja_env.filters['decompress'] = flt.decompress
        self._app.jinja_env.filters['dict_to_json'] = json.dumps
        self._app.jinja_env.filters['firmware_detail_tabular_field'] = self._render_firmware_detail_tabular_field
        self._app.jinja_env.filters['fix_cwe'] = flt.fix_cwe
        self._app.jinja_env.filters['format_duration'] = flt.format_duration
        self._app.jinja_env.filters['format_string_list_with_offset'] = flt.filter_format_string_list_with_offset
        self._app.jinja_env.filters['get_canvas_height'] = flt.get_canvas_height
        self._app.jinja_env.filters['get_searchable_crypto_block'] = flt.get_searchable_crypto_block
        self._app.jinja_env.filters['get_unique_keys_from_list_of_dicts'] = flt.get_unique_keys_from_list_of_dicts
        self._app.jinja_env.filters['hex'] = hex
        self._app.jinja_env.filters['hide_dts_binary_data'] = flt.hide_dts_binary_data
        self._app.jinja_env.filters['infection_color'] = flt.infection_color
        self._app.jinja_env.filters['is_list'] = lambda item: isinstance(item, list)
        self._app.jinja_env.filters['json_dumps'] = json.dumps
        self._app.jinja_env.filters['link_cve'] = flt.replace_cve_with_link
        self._app.jinja_env.filters['link_cwe'] = flt.replace_cwe_with_link
        self._app.jinja_env.filters['list_group'] = flt.list_group
        self._app.jinja_env.filters['list_group_collapse'] = flt.list_group_collapse
        self._app.jinja_env.filters['list_to_line_break_string'] = flt.list_to_line_break_string
        self._app.jinja_env.filters['list_to_line_break_string_no_sort'] = flt.list_to_line_break_string_no_sort
        self._app.jinja_env.filters['md5_hash'] = get_md5
        self._app.jinja_env.filters['min'] = min
        self._app.jinja_env.filters['nice_generic'] = flt.generic_nice_representation
        self._app.jinja_env.filters['nice_number'] = flt.nice_number_filter
        self._app.jinja_env.filters['nice_time'] = time_format
        self._app.jinja_env.filters['nice_uid_list'] = self._filter_nice_uid_list
        self._app.jinja_env.filters['nice_unix_time'] = flt.nice_unix_time
        self._app.jinja_env.filters['nice_virtual_path_list'] = self._nice_virtual_path_list
        self._app.jinja_env.filters['number_format'] = flt.byte_number_filter
        self._app.jinja_env.filters['print_program_version'] = self._filter_print_program_version
        self._app.jinja_env.filters['regex_meta'] = flt.comment_out_regex_meta_chars
        self._app.jinja_env.filters['remaining_time'] = elapsed_time
        self._app.jinja_env.filters['render_analysis_tags'] = flt.render_analysis_tags
        self._app.jinja_env.filters['render_general_information'] = self._render_general_information_table
        self._app.jinja_env.filters['render_query_title'] = flt.render_query_title
        self._app.jinja_env.filters['render_fw_tags'] = flt.render_fw_tags
        self._app.jinja_env.filters['replace_comparison_uid_with_hid'] = self._filter_replace_comparison_uid_with_hid
        self._app.jinja_env.filters['replace_uid_with_file_name'] = self._filter_replace_uid_with_file_name
        self._app.jinja_env.filters['replace_uid_with_hid_link'] = self._filter_replace_uid_with_hid_link
        self._app.jinja_env.filters['replace_uid_with_hid'] = self._filter_replace_uid_with_hid
        self._app.jinja_env.filters['replace_underscore'] = flt.replace_underscore_filter
        self._app.jinja_env.filters['version_is_compatible'] = flt.version_is_compatible
        self._app.jinja_env.filters['sort_chart_list_by_name'] = flt.sort_chart_list_by_name
        self._app.jinja_env.filters['sort_chart_list_by_value'] = flt.sort_chart_list_by_value
        self._app.jinja_env.filters['sort_comments'] = flt.sort_comments
        self._app.jinja_env.filters['sort_cve'] = flt.sort_cve_results
        self._app.jinja_env.filters['sort_privileges'] = lambda privileges: sorted(
            privileges, key=lambda role: len(privileges[role]), reverse=True
        )
        self._app.jinja_env.filters['sort_roles'] = flt.sort_roles_by_number_of_privileges
        self._app.jinja_env.filters['sort_users'] = flt.sort_users_by_name
        self._app.jinja_env.filters['split_user_and_password_type'] = self._split_user_and_password_type_entry
        self._app.jinja_env.filters['text_highlighter'] = flt.text_highlighter
        self._app.jinja_env.filters['uids_to_link'] = flt.uids_to_link
        self._app.jinja_env.filters['user_has_role'] = flt.user_has_role
        self._app.jinja_env.filters['version_links'] = flt.create_firmware_version_links
        self._app.jinja_env.filters['vulnerability_class'] = flt.vulnerability_class

        self._app.jinja_env.filters['_linter_reformat_issues'] = flt.linter_reformat_issues

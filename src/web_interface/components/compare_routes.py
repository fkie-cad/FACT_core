from __future__ import annotations

import logging
from contextlib import suppress
from typing import NamedTuple

from flask import redirect, render_template, render_template_string, request, session, url_for

from helperFunctions.data_conversion import (
    convert_compare_id_to_list,
    convert_uid_list_to_compare_id,
    normalize_compare_id,
)
from helperFunctions.database import ConnectTo, get_shared_session
from helperFunctions.web_interface import get_template_as_string
from web_interface.components.component_base import GET, AppRoute, ComponentBase
from web_interface.pagination import extract_pagination_from_request, get_pagination
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

# pylint: disable=no-self-use


class FileDiffData(NamedTuple):
    uid: str
    mime: str
    fw_hid: str


class CompareRoutes(ComponentBase):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    @roles_accepted(*PRIVILEGES['compare'])
    @AppRoute('/compare/<compare_id>', GET)
    def show_compare_result(self, compare_id):
        compare_id = normalize_compare_id(compare_id)
        with get_shared_session(self.db.comparison) as comparison_db:
            if not comparison_db.objects_exist(compare_id):
                return render_template('compare/error.html', error='Not all UIDs found in the DB')
            result = comparison_db.get_comparison_result(compare_id)
        if not result:
            return render_template('compare/wait.html', compare_id=compare_id)
        download_link = self._create_ida_download_if_existing(result, compare_id)
        uid_list = convert_compare_id_to_list(compare_id)
        plugin_views, plugins_without_view = self._get_compare_plugin_views(result)
        compare_view = _get_compare_view(plugin_views)
        self._fill_in_empty_fields(result, compare_id)
        return render_template_string(
            compare_view,
            result=result,
            uid_list=uid_list,
            download_link=download_link,
            plugins_without_view=plugins_without_view,
        )

    @staticmethod
    def _fill_in_empty_fields(result, compare_id):
        compare_uids = compare_id.split(';')
        for key in result['general']:
            for uid in compare_uids:
                if uid not in result['general'][key]:
                    result['general'][key][uid] = ''

    def _get_compare_plugin_views(self, compare_result):
        views, plugins_without_view = [], []
        with suppress(KeyError):
            used_plugins = list(compare_result['plugins'].keys())
            with get_shared_session(self.db.template) as template_db:
                for plugin in used_plugins:
                    view = template_db.get_view(plugin)
                    if view:
                        views.append((plugin, view))
                    else:
                        plugins_without_view.append(plugin)
        return views, plugins_without_view

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/compare', GET)
    def start_compare(self):
        uid_dict = get_comparison_uid_dict_from_session()
        if len(uid_dict) < 2:
            return render_template('compare/error.html', error='No UIDs found for comparison')

        comparison_id = convert_uid_list_to_compare_id(list(uid_dict))
        session['uids_for_comparison'] = None
        redo = True if request.args.get('force_recompare') else None

        with get_shared_session(self.db.comparison) as comparison_db:
            if not comparison_db.objects_exist(comparison_id):
                return render_template('compare/error.html', error='Not all UIDs found in the DB')

            if not redo and comparison_db.comparison_exists(comparison_id):
                return redirect(url_for('show_compare_result', compare_id=comparison_id))

        with ConnectTo(self.intercom) as sc:
            sc.add_compare_task(comparison_id, force=redo)
        return render_template('compare/wait.html', compare_id=comparison_id)

    @staticmethod
    def _create_ida_download_if_existing(result, compare_id):
        if isinstance(result, dict) and result.get('plugins', {}).get('Ida_Diff_Highlighting', {}).get('idb_binary'):
            return f'/ida-download/{compare_id}'
        return None

    @roles_accepted(*PRIVILEGES['compare'])
    @AppRoute('/database/browse_compare', GET)
    def browse_comparisons(self):
        with get_shared_session(self.db.comparison) as comparison_db:
            page, per_page = extract_pagination_from_request(request)[0:2]
            try:
                compare_list = comparison_db.page_comparison_results(skip=per_page * (page - 1), limit=per_page)
            except Exception as exception:  # pylint: disable=broad-except
                error_message = f'Could not query database: {type(exception)}'
                logging.error(error_message, exc_info=True)
                return render_template('error.html', message=error_message)

            total = comparison_db.get_total_number_of_results()

        pagination = get_pagination(page=page, per_page=per_page, total=total, record_name='compare results')
        return render_template(
            'database/compare_browse.html',
            compare_list=compare_list,
            page=page,
            per_page=per_page,
            pagination=pagination,
        )

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/comparison/add/<uid>', GET)
    @AppRoute('/comparison/add/<uid>/<root_uid>', GET)
    def add_to_compare_basket(self, uid, root_uid=None):
        compare_uid_list = get_comparison_uid_dict_from_session()
        compare_uid_list[uid] = root_uid
        session.modified = True  # pylint: disable=assigning-non-slot
        return redirect(url_for('show_analysis', uid=uid, root_uid=root_uid))

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/comparison/remove/<analysis_uid>/<compare_uid>', GET)
    @AppRoute('/comparison/remove/<analysis_uid>/<compare_uid>/<root_uid>', GET)
    def remove_from_compare_basket(self, analysis_uid, compare_uid, root_uid=None):
        compare_uid_list = get_comparison_uid_dict_from_session()
        if compare_uid in compare_uid_list:
            session['uids_for_comparison'].pop(compare_uid)
            session.modified = True  # pylint: disable=assigning-non-slot
        return redirect(url_for('show_analysis', uid=analysis_uid, root_uid=root_uid))

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/comparison/remove_all/<analysis_uid>', GET)
    @AppRoute('/comparison/remove_all/<analysis_uid>/<root_uid>', GET)
    def remove_all_from_compare_basket(self, analysis_uid, root_uid=None):
        compare_uid_list = get_comparison_uid_dict_from_session()
        compare_uid_list.clear()
        session.modified = True  # pylint: disable=assigning-non-slot
        return redirect(url_for('show_analysis', uid=analysis_uid, root_uid=root_uid))

    @roles_accepted(*PRIVILEGES['compare'])
    @AppRoute('/comparison/text_files', GET)
    def start_text_file_comparison(self):
        uids_dict = get_comparison_uid_dict_from_session()
        if len(uids_dict) != 2:
            return render_template(
                'compare/error.html', error=f'Can\'t compare {len(uids_dict)} files. You must select exactly 2 files.'
            )
        (uid_1, root_uid_1), (uid_2, root_uid_2) = list(uids_dict.items())
        uids_dict.clear()
        session.modified = True  # pylint: disable=assigning-non-slot
        return redirect(
            url_for('compare_text_files', uid_1=uid_1, uid_2=uid_2, root_uid_1=root_uid_1, root_uid_2=root_uid_2)
        )

    @roles_accepted(*PRIVILEGES['compare'])
    @AppRoute('/comparison/text_files/<uid_1>/<uid_2>', GET)
    @AppRoute('/comparison/text_files/<uid_1>/<uid_2>/<root_uid_1>/<root_uid_2>', GET)
    def compare_text_files(self, uid_1: str, uid_2: str, root_uid_1: str | None = None, root_uid_2: str | None = None):
        diff_files = [
            self._get_data_for_file_diff(uid_1, root_uid_1),
            self._get_data_for_file_diff(uid_2, root_uid_2),
        ]

        uids_with_missing_file_type = ', '.join(f.uid for f in diff_files if f.mime is None)
        if uids_with_missing_file_type:
            return render_template(
                'compare/error.html', error=f'file_type analysis is not finished for {uids_with_missing_file_type}'
            )

        if any(not f.mime.startswith('text') for f in diff_files):
            return render_template(
                'compare/error.html',
                error=f'Can\'t compare non-text mimetypes. ({diff_files[0].mime} vs {diff_files[1].mime})',
            )

        with ConnectTo(self.intercom) as intercom:
            diff_str = intercom.get_file_diff((uid_1, uid_2))
        if diff_str is None:
            return render_template('compare/error.html', error='File(s) not found.')

        return render_template(
            'compare/text_files.html', diffstr=diff_str, hid0=diff_files[0].fw_hid, hid1=diff_files[1].fw_hid
        )

    def _get_data_for_file_diff(self, uid: str, root_uid: str | None) -> FileDiffData:
        with get_shared_session(self.db.frontend) as frontend_db:
            fo = frontend_db.get_object(uid)
            if root_uid in [None, 'None']:
                root_uid = fo.get_root_uid()
            fw_hid = frontend_db.get_object(root_uid).get_hid()
        mime = fo.processed_analysis.get('file_type', {}).get('result', {}).get('mime')
        return FileDiffData(uid, mime, fw_hid)


def _get_compare_view(plugin_views):
    compare_view = get_template_as_string('compare/compare.html')
    return _add_plugin_views_to_compare_view(compare_view, plugin_views)


def _add_plugin_views_to_compare_view(compare_view, plugin_views):
    key = '{# individual plugin views #}'
    insertion_index = compare_view.find(key)
    if insertion_index == -1:
        logging.error('compare view insertion point not found in compare template')
    else:
        insertion_index += len(key)
        for plugin, view in plugin_views:
            if_case = f'{{% elif plugin == \'{plugin}\' %}}'
            view = f'{if_case}\n{view.decode()}'
            compare_view = _insert_plugin_into_view_at_index(view, compare_view, insertion_index)
    return compare_view


def _insert_plugin_into_view_at_index(plugin, view, index):
    if index < 0:
        return view
    return view[:index] + plugin + view[index:]


def get_comparison_uid_dict_from_session():  # pylint: disable=invalid-name
    # session['uids_for_comparison'] is a dictionary where keys are FileObject-
    # uids and values are the root FirmwareObject of the corresponding key
    if 'uids_for_comparison' not in session or not isinstance(session['uids_for_comparison'], dict):
        session['uids_for_comparison'] = {}
    return session['uids_for_comparison']

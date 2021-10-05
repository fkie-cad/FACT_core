import difflib
import logging
from contextlib import suppress

from flask import redirect, render_template, render_template_string, request, session, url_for

from helperFunctions.data_conversion import (
    convert_compare_id_to_list, convert_uid_list_to_compare_id, normalize_compare_id
)
from helperFunctions.database import ConnectTo
from helperFunctions.web_interface import get_template_as_string
from intercom.front_end_binding import InterComFrontEndBinding
from storage.binary_service import BinaryService
from storage.db_interface_compare import CompareDbInterface, FactCompareException
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_view_sync import ViewReader
from web_interface.components.component_base import GET, AppRoute, ComponentBase
from web_interface.pagination import extract_pagination_from_request, get_pagination
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class CompareRoutes(ComponentBase):
    @roles_accepted(*PRIVILEGES['compare'])
    @AppRoute('/compare/<compare_id>', GET)
    def show_compare_result(self, compare_id):
        compare_id = normalize_compare_id(compare_id)
        try:
            with ConnectTo(CompareDbInterface, self._config) as sc:
                result = sc.get_compare_result(compare_id)
        except FactCompareException as exception:
            return render_template('compare/error.html', error=exception.get_message())
        if not result:
            return render_template('compare/wait.html', compare_id=compare_id)
        download_link = self._create_ida_download_if_existing(result, compare_id)
        uid_list = convert_compare_id_to_list(compare_id)
        plugin_views, plugins_without_view = self._get_compare_plugin_views(result)
        compare_view = self._get_compare_view(plugin_views)
        self._fill_in_empty_fields(result, compare_id)
        return render_template_string(
            compare_view,
            result=result,
            uid_list=uid_list,
            download_link=download_link,
            plugins_without_view=plugins_without_view
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
            for plugin in used_plugins:
                with ConnectTo(ViewReader, self._config) as vr:
                    view = vr.get_view(plugin)
                if view:
                    views.append((plugin, view))
                else:
                    plugins_without_view.append(plugin)
        return views, plugins_without_view

    def _get_compare_view(self, plugin_views):
        compare_view = get_template_as_string('compare/compare.html')
        return self._add_plugin_views_to_compare_view(compare_view, plugin_views)

    def _add_plugin_views_to_compare_view(self, compare_view, plugin_views):
        key = '{# individual plugin views #}'
        insertion_index = compare_view.find(key)
        if insertion_index == -1:
            logging.error('compare view insertion point not found in compare template')
        else:
            insertion_index += len(key)
            for plugin, view in plugin_views:
                if_case = '{{% elif plugin == \'{}\' %}}'.format(plugin)
                view = '{}\n{}'.format(if_case, view.decode())
                compare_view = self._insert_plugin_into_view_at_index(view, compare_view, insertion_index)
        return compare_view

    @staticmethod
    def _insert_plugin_into_view_at_index(plugin, view, index):
        if index < 0:
            return view
        return view[:index] + plugin + view[index:]

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/compare', GET)
    def start_compare(self):
        if 'uids_for_comparison' not in session or not isinstance(session['uids_for_comparison'], list) or len(session['uids_for_comparison']) < 2:
            return render_template('compare/error.html', error='No UIDs found for comparison')
        compare_id = convert_uid_list_to_compare_id(session['uids_for_comparison'])
        session['uids_for_comparison'] = None
        redo = True if request.args.get('force_recompare') else None

        with ConnectTo(CompareDbInterface, self._config) as sc:
            compare_exists = sc.compare_result_is_in_db(compare_id)
        if compare_exists and not redo:
            return redirect(url_for('show_compare_result', compare_id=compare_id))

        try:
            with ConnectTo(CompareDbInterface, self._config) as sc:
                sc.check_objects_exist(compare_id)
        except FactCompareException as exception:
            return render_template('compare/error.html', error=exception.get_message())

        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            sc.add_compare_task(compare_id, force=redo)
        return render_template('compare/wait.html', compare_id=compare_id)

    @staticmethod
    def _create_ida_download_if_existing(result, compare_id):
        if isinstance(result, dict) and result.get('plugins', dict()).get('Ida_Diff_Highlighting', dict()).get('idb_binary'):
            return '/ida-download/{}'.format(compare_id)
        return None

    @roles_accepted(*PRIVILEGES['compare'])
    @AppRoute('/database/browse_compare', GET)
    def browse_comparisons(self):
        page, per_page = extract_pagination_from_request(request, self._config)[0:2]
        try:
            with ConnectTo(CompareDbInterface, self._config) as db_service:
                compare_list = db_service.page_compare_results(skip=per_page * (page - 1), limit=per_page)
        except Exception as exception:
            error_message = 'Could not query database: {} {}'.format(type(exception), str(exception))
            logging.error(error_message)
            return render_template('error.html', message=error_message)

        with ConnectTo(CompareDbInterface, self._config) as connection:
            total = connection.get_total_number_of_results()

        pagination = get_pagination(page=page, per_page=per_page, total=total, record_name='compare results')
        return render_template('database/compare_browse.html', compare_list=compare_list, page=page, per_page=per_page, pagination=pagination)

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/comparison/add/<uid>', GET)
    def add_to_compare_basket(self, uid):  # pylint: disable=no-self-use
        compare_uid_list = get_comparison_uid_list_from_session()
        compare_uid_list.append(uid)
        session.modified = True
        return redirect(url_for('show_analysis', uid=uid))

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/comparison/remove/<analysis_uid>/<compare_uid>', GET)
    def remove_from_compare_basket(self, analysis_uid, compare_uid):  # pylint: disable=no-self-use
        compare_uid_list = get_comparison_uid_list_from_session()
        if compare_uid in compare_uid_list:
            session['uids_for_comparison'].remove(compare_uid)
            session.modified = True
        return redirect(url_for('show_analysis', uid=analysis_uid))

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/comparison/remove_all/<analysis_uid>', GET)
    def remove_all_from_compare_basket(self, analysis_uid):  # pylint: disable=no-self-use
        compare_uid_list = get_comparison_uid_list_from_session()
        compare_uid_list.clear()
        session.modified = True
        return redirect(url_for('show_analysis', uid=analysis_uid))

    @roles_accepted(*PRIVILEGES['compare'])
    @AppRoute('/comparison/text_files', GET)
    def text_files(self):
        compare_uid_list = get_comparison_uid_list_from_session()
        if len(compare_uid_list) != 2:
            return render_template('compare/error.html', error=f"Can't compare {len(compare_uid_list)} files. You must compare exactly 2 files.")

        uids = [session['uids_for_comparison'][0], session['uids_for_comparison'][1]]
        contents = [None, None]
        names = [None, None]
        fos = [None, None]
        bs = BinaryService(self._config)
        contents[0], names[0] = bs.get_binary_and_file_name(uids[0])
        contents[1], names[1] = bs.get_binary_and_file_name(uids[1])

        with ConnectTo(CompareDbInterface, self._config) as db:
            fos[0] = db.get_object(uids[0])
            fos[1] = db.get_object(uids[1])

        # FIXME theoretically it is possible that the file_type plugin is not finished yet.
        mimetypes = [None, None]
        mimetypes[0] = fos[0].processed_analysis['file_type']['mime']
        mimetypes[1] = fos[1].processed_analysis['file_type']['mime']

        if mimetypes[0][0:len('text')] != 'text' or mimetypes[1][0:len('text')] != 'text':
            return render_template('compare/error.html', error=f"Can't compare non-text mimetypes. ({mimetypes[0]} vs {mimetypes[1]})")

        # Note that this is kind of bad.
        # Files can be part of many firmwares. This means that two firmwares containing the same file might lead to
        # confusion.
        root_uids = [fos[0].get_root_uid(), fos[1].get_root_uid()]
        with ConnectTo(FrontEndDbInterface, self._config) as db:
            firmwares = [db.get_object(root_uids[0]), db.get_object(root_uids[1])]

        diff_generator = difflib.unified_diff(contents[0].decode().splitlines(keepends=True),
                                              contents[1].decode().splitlines(keepends=True),
                                              fromfile=f'{names[0]}',
                                              tofile=f'{names[1]}')

        diffstr = ''.join(diff_generator)
        diffstr = diffstr.replace('`', '\\`')
        return render_template('compare/text_files.html', diffstr=diffstr, file0=names[0], file1=names[1], fw0=firmwares[0], fw1=firmwares[1])

    def get_software_components(self, uid):
        try:
            with ConnectTo(CompareDbInterface, self._config) as db:
                components = db.get_object(uid).processed_analysis['software_components']['summary']
        except KeyError:
            components = None
        return components


def get_comparison_uid_list_from_session():  # pylint: disable=invalid-name
    if 'uids_for_comparison' not in session or not isinstance(session['uids_for_comparison'], list):
        session['uids_for_comparison'] = []
    return session['uids_for_comparison']

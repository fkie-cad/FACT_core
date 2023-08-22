from __future__ import annotations

import json
import logging
import os
from contextlib import suppress
from typing import TYPE_CHECKING

from common_helper_files import get_binary_from_file
from flask import flash, redirect, render_template, render_template_string, request, url_for
from flask_login.utils import current_user

import config
from helperFunctions.data_conversion import none_to_none
from helperFunctions.database import get_shared_session
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.task_conversion import check_for_errors, convert_analysis_task_to_fw_obj, create_re_analyze_task
from helperFunctions.web_interface import get_template_as_string
from objects.firmware import Firmware
from web_interface.components.compare_routes import get_comparison_uid_dict_from_session
from web_interface.components.component_base import AppRoute, ComponentBase, GET, POST
from web_interface.components.dependency_graph import (
    create_data_graph_edges,
    create_data_graph_nodes_and_groups,
    get_graph_colors,
)
from web_interface.security.authentication import user_has_privilege
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

if TYPE_CHECKING:
    from helperFunctions.types import UID
    from objects.file import FileObject


def get_analysis_view(view_name):
    view_path = os.path.join(  # noqa: PTH118
        get_src_dir(), f'web_interface/templates/analysis_plugins/{view_name}.html'
    )
    return get_binary_from_file(view_path).decode('utf-8')


class AnalysisRoutes(ComponentBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.analysis_generic_view = get_analysis_view('generic')
        self.analysis_unpacker_view = get_analysis_view('unpacker')

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @AppRoute('/analysis/<uid>', GET)
    @AppRoute('/analysis/<uid>/ro/<root_uid>', GET)
    @AppRoute('/analysis/<uid>/<selected_analysis>', GET)
    @AppRoute('/analysis/<uid>/<selected_analysis>/ro/<root_uid>', GET)
    def show_analysis(self, uid, selected_analysis=None, root_uid=None):
        other_versions = None
        all_comparisons = self.db.comparison.page_comparison_results()
        with get_shared_session(self.db.frontend) as frontend_db:
            known_comparisons = [comparison for comparison in all_comparisons if uid in comparison[0]]
            file_obj = frontend_db.get_object(uid)
            if not file_obj:
                return render_template('uid_not_found.html', uid=uid)
            if selected_analysis is not None and selected_analysis not in file_obj.processed_analysis:
                return render_template(
                    'error.html', message=f'The requested analysis ({selected_analysis}) has not run (yet)'
                )
            if isinstance(file_obj, Firmware):
                root_uid = file_obj.uid
                other_versions = frontend_db.get_other_versions_of_firmware(file_obj)
            included_fo_analysis_complete = not frontend_db.all_uids_found_in_database(list(file_obj.files_included))
            file_tree_paths = (
                frontend_db.get_file_tree_path(uid, root_uid=none_to_none(root_uid))
                if not isinstance(file_obj, Firmware)
                else [[file_obj.uid]]
            )
        analysis_plugins = self.intercom.get_available_analysis_plugins()

        analysis = file_obj.processed_analysis.get(selected_analysis, {})

        return render_template_string(
            self._get_correct_template(selected_analysis, file_obj),
            uid=uid,
            firmware=file_obj,
            file_tree_paths=file_tree_paths,
            analysis_result=analysis.get('result', {}),
            analysis_metadata={k: v for k, v in analysis.items() if k != 'result'},
            selected_analysis=selected_analysis,
            all_analyzed_flag=included_fo_analysis_complete,
            root_uid=none_to_none(root_uid),
            analysis_plugin_dict=analysis_plugins,
            other_versions=other_versions,
            uids_for_comparison=get_comparison_uid_dict_from_session(),
            user_has_admin_clearance=user_has_privilege(current_user, privilege='delete'),
            known_comparisons=known_comparisons,
            available_plugins=self._get_used_and_unused_plugins(
                file_obj.processed_analysis, [x for x in analysis_plugins if x != 'unpacker']
            ),
        )

    def _get_correct_template(self, selected_analysis: str | None, fw_object: Firmware | FileObject):
        if selected_analysis and 'failed' in fw_object.processed_analysis[selected_analysis].get('result', {}):
            return get_template_as_string('analysis_plugins/fail.html')
        if selected_analysis:
            return self._get_analysis_view(selected_analysis)
        return get_template_as_string('show_analysis.html')

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/analysis/<uid>', POST)
    @AppRoute('/analysis/<uid>/ro/<root_uid>', POST)
    @AppRoute('/analysis/<uid>/<selected_analysis>', POST)
    @AppRoute('/analysis/<uid>/<selected_analysis>/ro/<root_uid>', POST)
    def start_single_file_analysis(self, uid, selected_analysis=None, root_uid=None):
        file_object = self.db.frontend.get_object(uid)
        if file_object is None:
            return render_template('uid_not_found.html', uid=uid)
        file_object.scheduled_analysis = request.form.getlist('analysis_systems')
        file_object.temporary_data['force_update'] = request.form.get('force_update') == 'true'
        self.intercom.add_single_file_task(file_object)
        return redirect(
            url_for(self.show_analysis.__name__, uid=uid, root_uid=root_uid, selected_analysis=selected_analysis)
        )

    @staticmethod
    def _get_used_and_unused_plugins(processed_analysis: dict, all_plugins: list) -> dict:
        return {
            'unused': [x for x in all_plugins if x not in processed_analysis],
            'used': [x for x in all_plugins if x in processed_analysis],
        }

    def _get_analysis_view(self, selected_analysis):
        if selected_analysis == 'unpacker':
            return self.analysis_unpacker_view
        view = self.db.template.get_view(selected_analysis)
        if view:
            return view.decode('utf-8')
        return self.analysis_generic_view

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/update-analysis/<uid>', GET)
    def get_update_analysis(self, uid, re_do=False, error=None):
        with get_shared_session(self.db.frontend) as frontend_db:
            old_firmware = frontend_db.get_object(uid=uid)
            if old_firmware is None or not isinstance(old_firmware, Firmware):
                return render_template('uid_not_found.html', uid=uid)

            device_class_list = frontend_db.get_device_class_list()
            vendor_list = frontend_db.get_vendor_list()
            device_name_dict = frontend_db.get_device_name_dict()

        plugin_dict = self.intercom.get_available_analysis_plugins()

        current_analysis_preset = _add_preset_from_firmware(plugin_dict, old_firmware)
        analysis_presets = [current_analysis_preset, *list(config.frontend.analysis_preset)]

        title = 're-do analysis' if re_do else 'update analysis'

        return render_template(
            'upload/upload.html',
            device_classes=device_class_list,
            vendors=vendor_list,
            error=error if error is not None else {},
            device_names=json.dumps(device_name_dict, sort_keys=True),
            firmware=old_firmware,
            analysis_plugin_dict=plugin_dict,
            analysis_presets=analysis_presets,
            title=title,
            plugin_set=current_analysis_preset,
        )

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/update-analysis/<uid>', POST)
    def post_update_analysis(self, uid, re_do=False):
        analysis_task = create_re_analyze_task(request, uid=uid)
        force_reanalysis = request.form.get('force_reanalysis') == 'true'
        if error := check_for_errors(analysis_task):
            return self.get_update_analysis(uid=uid, re_do=re_do, error=error)
        try:
            self._schedule_re_analysis_task(uid, analysis_task, re_do, force_reanalysis)
        except RuntimeError as exception:
            logging.error(str(exception))
            flash(f'Error: {exception}', 'danger')
            return self.get_update_analysis(uid=uid, re_do=re_do)
        return render_template('upload/upload_successful.html', uid=uid)

    def _schedule_re_analysis_task(self, uid: UID, analysis_task: dict, re_do: bool, force_reanalysis: bool):
        if re_do:
            analysis_task['binary'] = self._get_binary(uid)
            base_fw = None
            self.db.admin.delete_firmware(uid, delete_root_file=False)
        else:
            base_fw = self._get_base_fw(uid)
            base_fw.temporary_data['force_update'] = force_reanalysis
        fw = convert_analysis_task_to_fw_obj(analysis_task, base_fw=base_fw)
        self.intercom.add_re_analyze_task(fw, unpack=re_do)

    def _get_base_fw(self, uid: UID) -> Firmware:
        base_fw = self.db.frontend.get_object(uid)
        if isinstance(base_fw, Firmware):
            return base_fw
        raise RuntimeError(f'Firmware with UID "{uid}" not found in the database')

    def _get_binary(self, uid: UID) -> bytes:
        response = self.intercom.get_binary_and_filename(uid)
        if not response:
            raise RuntimeError('Timeout when loading binary from backend')
        binary, _ = response
        if not binary:
            raise RuntimeError('Binary not found')
        return binary

    @roles_accepted(*PRIVILEGES['delete'])
    @AppRoute('/admin/re-do_analysis/<uid>', GET, POST)
    def redo_analysis(self, uid: str):
        if request.method == POST:
            return self.post_update_analysis(uid, re_do=True)
        return self.get_update_analysis(uid, re_do=True)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @AppRoute('/dependency-graph/<uid>/<root_uid>', GET)
    def show_elf_dependency_graph(self, uid: str, root_uid: str):
        with get_shared_session(self.db.frontend) as frontend_db:
            if root_uid in [None, 'None']:
                root_uid = frontend_db.get_root_uid(uid)
            data = frontend_db.get_data_for_dependency_graph(uid)

        whitelist = [
            'application/x-executable',
            'application/x-pie-executable',
            'application/x-sharedlib',
            'inode/symlink',
        ]
        data_graph_part = create_data_graph_nodes_and_groups(data, whitelist)
        colors = sorted(get_graph_colors(len(data_graph_part['groups'])))
        if not data_graph_part['nodes']:
            flash(
                'Error: Graph could not be rendered. '
                'The file chosen as root must contain a filesystem with binaries.',
                'danger',
            )
            return render_template('dependency_graph.html', **data_graph_part, uid=uid, root_uid=root_uid)

        data_graph, elf_analysis_missing_from_files = create_data_graph_edges(data_graph_part)
        if elf_analysis_missing_from_files > 0:
            flash(
                f'Warning: Elf analysis plugin result is missing for {elf_analysis_missing_from_files} files', 'warning'
            )

        # FixMe: Add a loading icon?
        return render_template(
            'dependency_graph.html',
            **{key: json.dumps(data_graph[key]) for key in ['nodes', 'edges', 'groups']},
            uid=uid,
            root_uid=root_uid,
            colors=colors,
        )


def _add_preset_from_firmware(plugin_dict, fw: Firmware):
    """
    Adds a preset to plugin_dict with all plugins ticked that are processed on the firmware fw.
    Returns the name of the new preset.
    """
    preset_name = fw.uid

    previously_processed_plugins = list(fw.processed_analysis.keys())
    with suppress(ValueError):
        plugin_dict.pop('unpacker')
        previously_processed_plugins.remove('unpacker')
    for plugin in previously_processed_plugins:
        if plugin in plugin_dict:
            plugin_dict[plugin][2][preset_name] = True
        else:
            logging.warning(f'Previously used analysis plugin {plugin} not found for update preset')

    return preset_name

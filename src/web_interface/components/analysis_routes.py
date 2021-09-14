import json
import os
from typing import Dict, Union

from common_helper_files import get_binary_from_file
from flask import flash, redirect, render_template, render_template_string, request, url_for
from flask_login.utils import current_user

from helperFunctions.data_conversion import none_to_none
from helperFunctions.database import ConnectTo
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.mongo_task_conversion import (
    check_for_errors, convert_analysis_task_to_fw_obj, create_re_analyze_task
)
from helperFunctions.web_interface import get_template_as_string
from intercom.front_end_binding import InterComFrontEndBinding
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_compare import CompareDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_view_sync import ViewReader
from web_interface.components.compare_routes import get_comparison_uid_list_from_session
from web_interface.components.component_base import GET, POST, AppRoute, ComponentBase
from web_interface.components.dependency_graph import (
    create_data_graph_edges, create_data_graph_nodes_and_groups, get_graph_colors
)
from web_interface.security.authentication import user_has_privilege
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


def get_analysis_view(view_name):
    view_path = os.path.join(get_src_dir(), f'web_interface/templates/analysis_plugins/{view_name}.html')
    return get_binary_from_file(view_path).decode('utf-8')


class AnalysisRoutes(ComponentBase):
    def __init__(self, app, config, api=None):
        super().__init__(app, config, api)
        self.analysis_generic_view = get_analysis_view('generic')
        self.analysis_unpacker_view = get_analysis_view('unpacker')

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @AppRoute('/analysis/<uid>', GET)
    @AppRoute('/analysis/<uid>/ro/<root_uid>', GET)
    @AppRoute('/analysis/<uid>/<selected_analysis>', GET)
    @AppRoute('/analysis/<uid>/<selected_analysis>/ro/<root_uid>', GET)
    def show_analysis(self, uid, selected_analysis=None, root_uid=None):
        other_versions = None
        with ConnectTo(CompareDbInterface, self._config) as db_service:
            all_comparisons = db_service.page_compare_results()
            known_comparisons = [comparison for comparison in all_comparisons if uid in comparison[0]]
        analysis_filter = [selected_analysis] if selected_analysis else []
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            file_obj = sc.get_object(uid, analysis_filter=analysis_filter)
            if not file_obj:
                return render_template('uid_not_found.html', uid=uid)
            if isinstance(file_obj, Firmware):
                root_uid = file_obj.uid
                other_versions = sc.get_other_versions_of_firmware(file_obj)
            included_fo_analysis_complete = not sc.all_uids_found_in_database(list(file_obj.files_included))
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            analysis_plugins = sc.get_available_analysis_plugins()
        return render_template_string(
            self._get_correct_template(selected_analysis, file_obj),
            uid=uid,
            firmware=file_obj,
            selected_analysis=selected_analysis,
            all_analyzed_flag=included_fo_analysis_complete,
            root_uid=none_to_none(root_uid),
            analysis_plugin_dict=analysis_plugins,
            other_versions=other_versions,
            uids_for_comparison=get_comparison_uid_list_from_session(),
            user_has_admin_clearance=user_has_privilege(current_user, privilege='delete'),
            known_comparisons=known_comparisons,
            available_plugins=self._get_used_and_unused_plugins(
                file_obj.processed_analysis,
                [x for x in analysis_plugins.keys() if x != 'unpacker']
            )
        )

    def _get_correct_template(self, selected_analysis: str, fw_object: Union[Firmware, FileObject]):
        if selected_analysis and 'failed' in fw_object.processed_analysis[selected_analysis]:
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
        with ConnectTo(FrontEndDbInterface, self._config) as database:
            file_object = database.get_object(uid)
        file_object.scheduled_analysis = request.form.getlist('analysis_systems')
        file_object.force_update = request.form.get('force_update') == 'true'
        with ConnectTo(InterComFrontEndBinding, self._config) as intercom:
            intercom.add_single_file_task(file_object)
        return redirect(url_for(self.show_analysis.__name__, uid=uid, root_uid=root_uid, selected_analysis=selected_analysis))

    @staticmethod
    def _get_used_and_unused_plugins(processed_analysis: dict, all_plugins: list) -> dict:
        return {
            'unused': [x for x in all_plugins if x not in processed_analysis],
            'used': [x for x in all_plugins if x in processed_analysis]
        }

    def _get_analysis_view(self, selected_analysis):
        if selected_analysis == 'unpacker':
            return self.analysis_unpacker_view
        with ConnectTo(ViewReader, self._config) as vr:
            view = vr.get_view(selected_analysis)
        if view:
            return view.decode('utf-8')
        return self.analysis_generic_view

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/update-analysis/<uid>', GET)
    def get_update_analysis(self, uid, re_do=False, error=None):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            old_firmware = sc.get_firmware(uid=uid, analysis_filter=[])
            if old_firmware is None:
                return render_template('uid_not_found.html', uid=uid)

            device_class_list = sc.get_device_class_list()
            vendor_list = sc.get_vendor_list()
            device_name_dict = sc.get_device_name_dict()

        device_class_list.remove(old_firmware.device_class)
        vendor_list.remove(old_firmware.vendor)
        device_name_dict[old_firmware.device_class][old_firmware.vendor].remove(old_firmware.device_name)

        previously_processed_plugins = list(old_firmware.processed_analysis.keys())
        with ConnectTo(InterComFrontEndBinding, self._config) as intercom:
            plugin_dict = self._overwrite_default_plugins(intercom.get_available_analysis_plugins(), previously_processed_plugins)

        title = 're-do analysis' if re_do else 'update analysis'

        return render_template(
            'upload/upload.html',
            device_classes=device_class_list,
            vendors=vendor_list,
            error=error if error is not None else {},
            device_names=json.dumps(device_name_dict, sort_keys=True),
            firmware=old_firmware,
            analysis_plugin_dict=plugin_dict,
            title=title
        )

    @staticmethod
    def _overwrite_default_plugins(plugin_dict: Dict[str, tuple], checked_plugin_list) -> Dict[str, tuple]:
        plugin_dict.pop('unpacker')  # FIXME: why is this even in there?
        for plugin in plugin_dict:
            plugin_dict[plugin][2]['default'] = plugin in checked_plugin_list
        return plugin_dict

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/update-analysis/<uid>', POST)
    def post_update_analysis(self, uid, re_do=False):
        analysis_task = create_re_analyze_task(request, uid=uid)
        error = check_for_errors(analysis_task)
        if error:
            return redirect(url_for('get_update_analysis', uid=uid, re_do=re_do, error=error))
        self._schedule_re_analysis_task(uid, analysis_task, re_do)
        return render_template('upload/upload_successful.html', uid=uid)

    def _schedule_re_analysis_task(self, uid, analysis_task, re_do):
        fw = convert_analysis_task_to_fw_obj(analysis_task)
        if re_do:
            with ConnectTo(AdminDbInterface, self._config) as sc:
                sc.delete_firmware(uid, delete_root_file=False)
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            sc.add_re_analyze_task(fw)

    @roles_accepted(*PRIVILEGES['delete'])
    @AppRoute('/admin/re-do_analysis/<uid>', GET, POST)
    def redo_analysis(self, uid):
        if request.method == POST:
            return self.post_update_analysis(uid, re_do=True)
        return self.get_update_analysis(uid, re_do=True)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @AppRoute('/dependency-graph/<uid>', GET)
    def show_elf_dependency_graph(self, uid):
        with ConnectTo(FrontEndDbInterface, self._config) as db:
            data = db.get_data_for_dependency_graph(uid)

            whitelist = ['application/x-executable', 'application/x-sharedlib', 'inode/symlink']

            data_graph_part = create_data_graph_nodes_and_groups(data, whitelist)

            if not data_graph_part['nodes']:
                flash('Error: Graph could not be rendered. '
                      'The file chosen as root must contain a filesystem with binaries.', 'danger')
                return render_template('dependency_graph.html', **data_graph_part, uid=uid)

            data_graph, elf_analysis_missing_from_files = create_data_graph_edges(data, data_graph_part)

            if elf_analysis_missing_from_files > 0:
                flash(f'Warning: Elf analysis plugin result is missing for {elf_analysis_missing_from_files} files', 'warning')

            color_list = get_graph_colors()

            # TODO: Add a loading icon?
        return render_template('dependency_graph.html', **data_graph, uid=uid, color_list=color_list)

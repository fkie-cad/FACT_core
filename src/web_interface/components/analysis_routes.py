import json
import os
from typing import Union

from common_helper_files import get_binary_from_file
from flask import flash, render_template, render_template_string, request
from flask_login.utils import current_user

from helperFunctions.database import ConnectTo
from helperFunctions.dataConversion import none_to_none
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.mongo_task_conversion import (
    check_for_errors, convert_analysis_task_to_fw_obj, create_re_analyze_task
)
from helperFunctions.web_interface import get_template_as_string, overwrite_default_plugins
from intercom.front_end_binding import InterComFrontEndBinding
from objects.file import FileObject
from objects.firmware import Firmware
from storage.db_interface_admin import AdminDbInterface
from storage.db_interface_compare import CompareDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from storage.db_interface_view_sync import ViewReader
from web_interface.components.compare_routes import get_comparison_uid_list_from_session
from web_interface.components.component_base import ComponentBase
from web_interface.security.authentication import user_has_privilege
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


def get_analysis_view(view_name):
    view_path = os.path.join(get_src_dir(), 'web_interface/templates/analysis_plugins/{}.html'.format(view_name))
    return get_binary_from_file(view_path).decode('utf-8')


class AnalysisRoutes(ComponentBase):

    analysis_generic_view = get_analysis_view('generic')
    analysis_unpacker_view = get_analysis_view('unpacker')

    def _init_component(self):
        self._app.add_url_rule('/update-analysis/<uid>', 'update-analysis/<uid>', self._update_analysis, methods=['GET', 'POST'])
        self._app.add_url_rule('/analysis/<uid>', 'analysis/<uid>', self._show_analysis_results, methods=['GET', 'POST'])
        self._app.add_url_rule('/analysis/<uid>/ro/<root_uid>', '/analysis/<uid>/ro/<root_uid>', self._show_analysis_results, methods=['GET', 'POST'])
        self._app.add_url_rule('/analysis/<uid>/<selected_analysis>', '/analysis/<uid>/<selected_analysis>', self._show_analysis_results, methods=['GET', 'POST'])
        self._app.add_url_rule('/analysis/<uid>/<selected_analysis>/ro/<root_uid>', '/analysis/<uid>/<selected_analysis>/<root_uid>', self._show_analysis_results, methods=['GET', 'POST'])
        self._app.add_url_rule('/admin/re-do_analysis/<uid>', '/admin/re-do_analysis/<uid>', self._re_do_analysis, methods=['GET', 'POST'])

    @staticmethod
    def _get_firmware_ids_including_this_file(fo):
        if isinstance(fo, Firmware):
            return None
        return list(fo.get_virtual_file_paths().keys())

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _show_analysis_results(self, uid, selected_analysis=None, root_uid=None):
        if request.method == 'POST':
            self._start_single_file_analysis(uid)

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
            firmware_including_this_fo=self._get_firmware_ids_including_this_file(file_obj),
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

    def _start_single_file_analysis(self, uid):
        if user_has_privilege(current_user, privilege='submit_analysis'):
            with ConnectTo(FrontEndDbInterface, self._config) as database:
                file_object = database.get_object(uid)
            file_object.scheduled_analysis = request.form.getlist('analysis_systems')
            with ConnectTo(InterComFrontEndBinding, self._config) as intercom:
                intercom.add_single_file_task(file_object)
        else:
            flash('You have insufficient rights to add additional analyses')

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
    def _update_analysis(self, uid, re_do=False):
        error = {}
        if request.method == 'POST':
            analysis_task = create_re_analyze_task(request, uid=uid)
            error = check_for_errors(analysis_task)
            if not error:
                self._schedule_re_analysis_task(uid, analysis_task, re_do)
                return render_template('upload/upload_successful.html', uid=uid)

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
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            plugin_dict = overwrite_default_plugins(sc, previously_processed_plugins)

        title = 're-do analysis' if re_do else 'update analysis'

        return render_template(
            'upload/re-analyze.html',
            device_classes=device_class_list,
            vendors=vendor_list,
            error=error,
            device_names=json.dumps(device_name_dict, sort_keys=True),
            firmware=old_firmware,
            analysis_plugin_dict=plugin_dict,
            title=title
        )

    def _schedule_re_analysis_task(self, uid, analysis_task, re_do):
        fw = convert_analysis_task_to_fw_obj(analysis_task)
        if re_do:
            with ConnectTo(AdminDbInterface, self._config) as sc:
                sc.delete_firmware(uid, delete_root_file=False)
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            sc.add_re_analyze_task(fw)

    @roles_accepted(*PRIVILEGES['delete'])
    def _re_do_analysis(self, uid):
        return self._update_analysis(uid, re_do=True)

import json
from tempfile import TemporaryDirectory
from time import sleep

import requests
from flask import make_response, redirect, render_template, request

from helperFunctions.database import ConnectTo
from helperFunctions.mongo_task_conversion import (
    check_for_errors, convert_analysis_task_to_fw_obj, create_analysis_task
)
from helperFunctions.pdf import build_pdf_report
from helperFunctions.web_interface import get_radare_endpoint
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface, FactCompareException
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class IORoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule('/upload', 'upload', self._app_upload, methods=['GET', 'POST'])
        self._app.add_url_rule('/download/<uid>', 'download/<uid>', self._app_download_binary)
        self._app.add_url_rule('/tar-download/<uid>', 'tar-download/<uid>', self._app_download_tar)
        self._app.add_url_rule('/ida-download/<compare_id>', 'ida-download/<compare_id>', self._download_ida_file)
        self._app.add_url_rule('/radare-view/<uid>', 'radare-view/<uid>', self._show_radare)
        self._app.add_url_rule('/pdf-download/<uid>', 'pdf-download/<uid>', self._download_pdf_report)

    # ---- upload
    @roles_accepted(*PRIVILEGES['submit_analysis'])
    def _app_upload(self):
        error = {}
        if request.method == 'POST':
            analysis_task = create_analysis_task(request)
            error = check_for_errors(analysis_task)
            if not error:
                fw = convert_analysis_task_to_fw_obj(analysis_task)
                with ConnectTo(InterComFrontEndBinding, self._config) as sc:
                    sc.add_analysis_task(fw)
                return render_template('upload/upload_successful.html', uid=analysis_task['uid'])

        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            device_class_list = sc.get_device_class_list()
            vendor_list = sc.get_vendor_list()
            device_name_dict = sc.get_device_name_dict()
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            analysis_plugins = sc.get_available_analysis_plugins()
        return render_template(
            'upload/upload.html',
            device_classes=device_class_list, vendors=vendor_list, error=error,
            analysis_presets=list(self._config['default_plugins']),
            device_names=json.dumps(device_name_dict, sort_keys=True), analysis_plugin_dict=analysis_plugins
        )

        # ---- file download

    @roles_accepted(*PRIVILEGES['download'])
    def _app_download_binary(self, uid):
        return self._prepare_file_download(uid, packed=False)

    @roles_accepted(*PRIVILEGES['download'])
    def _app_download_tar(self, uid):
        return self._prepare_file_download(uid, packed=True)

    def _prepare_file_download(self, uid, packed=False):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            if packed:
                result = sc.get_repacked_binary_and_file_name(uid)
            else:
                result = sc.get_binary_and_filename(uid)
        if result is None:
            return render_template('error.html', message='timeout')
        binary, file_name = result
        response = make_response(binary)
        response.headers['Content-Disposition'] = 'attachment; filename={}'.format(file_name)
        return response

    @roles_accepted(*PRIVILEGES['download'])
    def _download_ida_file(self, compare_id):
        try:
            with ConnectTo(CompareDbInterface, self._config) as sc:
                result = sc.get_compare_result(compare_id)
        except FactCompareException as exception:
            return render_template('error.html', message=exception.get_message())
        if result is None:
            return render_template('error.html', message='timeout')
        binary = result['plugins']['Ida_Diff_Highlighting']['idb_binary']
        response = make_response(binary)
        response.headers['Content-Disposition'] = 'attachment; filename={}.idb'.format(compare_id[:8])
        return response

    @roles_accepted(*PRIVILEGES['download'])
    def _show_radare(self, uid):
        host, post_path = get_radare_endpoint(self._config), '/v1/retrieve'
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        with ConnectTo(InterComFrontEndBinding, self._config) as sc:
            result = sc.get_binary_and_filename(uid)
        if result is None:
            return render_template('error.html', message='timeout')
        binary, _ = result
        try:
            response = requests.post('{}{}'.format(host, post_path), data=binary, verify=False)
            if response.status_code != 200:
                raise TimeoutError(response.text)
            target_link = '{}{}m/'.format(host, response.json()['endpoint'])
            sleep(1)
            return redirect(target_link)
        except Exception as exception:
            return render_template('error.html', message=str(exception))

    @roles_accepted(*PRIVILEGES['download'])
    def _download_pdf_report(self, uid):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)

        with ConnectTo(FrontEndDbInterface, self._config) as connection:
            firmware = connection.get_complete_object_including_all_summaries(uid)

        try:
            with TemporaryDirectory() as folder:
                binary, pdf_path = build_pdf_report(firmware, folder)
        except RuntimeError as error:
            return render_template('error.html', message=str(error))

        response = make_response(binary)
        response.headers['Content-Disposition'] = 'attachment; filename={}'.format(pdf_path.name)

        return response

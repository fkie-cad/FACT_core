import json
from pathlib import Path
from tempfile import TemporaryDirectory
from time import sleep

import requests
from flask import make_response, redirect, render_template, request

from helperFunctions.database import ConnectTo, get_shared_session
from helperFunctions.pdf import build_pdf_report
from helperFunctions.task_conversion import check_for_errors, convert_analysis_task_to_fw_obj, create_analysis_task
from web_interface.components.component_base import GET, POST, AppRoute, ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

from config import cfg


class IORoutes(ComponentBase):

    # ---- upload

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/upload', POST)
    def post_upload(self):
        analysis_task = create_analysis_task(request)
        error = check_for_errors(analysis_task)
        if error:
            return self.get_upload(error=error)
        fw = convert_analysis_task_to_fw_obj(analysis_task)
        with ConnectTo(self.intercom) as sc:
            sc.add_analysis_task(fw)
        return render_template('upload/upload_successful.html', uid=analysis_task['uid'])

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/upload', GET)
    def get_upload(self, error=None):
        error = error or {}
        with get_shared_session(self.db.frontend) as frontend_db:
            device_class_list = frontend_db.get_device_class_list()
            vendor_list = frontend_db.get_vendor_list()
            device_name_dict = frontend_db.get_device_name_dict()
        with ConnectTo(self.intercom) as sc:
            analysis_plugins = sc.get_available_analysis_plugins()
        return render_template(
            'upload/upload.html',
            device_classes=device_class_list, vendors=vendor_list, error=error,
            # TODO is this right?
            analysis_presets=list(cfg.default_plugins),
            device_names=json.dumps(device_name_dict, sort_keys=True), analysis_plugin_dict=analysis_plugins,
            plugin_set='default',
        )

    # ---- file download

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/download/<uid>', GET)
    def download_binary(self, uid):
        return self._prepare_file_download(uid, packed=False)

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/tar-download/<uid>', GET)
    def download_tar(self, uid):
        return self._prepare_file_download(uid, packed=True)

    def _prepare_file_download(self, uid, packed=False):
        if not self.db.frontend.exists(uid):
            return render_template('uid_not_found.html', uid=uid)
        with ConnectTo(self.intercom) as sc:
            if packed:
                result = sc.get_repacked_binary_and_file_name(uid)
            else:
                result = sc.get_binary_and_filename(uid)
        if result is None:
            return render_template('error.html', message='timeout')
        binary, file_name = result
        response = make_response(binary)
        response.headers['Content-Disposition'] = f'attachment; filename={file_name}'
        return response

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/ida-download/<compare_id>', GET)
    def download_ida_file(self, compare_id):
        # FixMe: IDA comparison plugin must not add binary strings to the result (not JSON compatible)
        result = self.db.comparison.get_comparison_result(compare_id)
        if result is None:
            return render_template('error.html', message=f'Comparison with ID {compare_id} not found')
        binary = result['plugins']['Ida_Diff_Highlighting']['idb_binary']
        response = make_response(binary)
        response.headers['Content-Disposition'] = f'attachment; filename={compare_id[:8]}.idb'
        return response

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/radare-view/<uid>', GET)
    def show_radare(self, uid):
        object_exists = self.db.frontend.exists(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        with ConnectTo(self.intercom) as sc:
            result = sc.get_binary_and_filename(uid)
        if result is None:
            return render_template('error.html', message='timeout')
        binary, _ = result
        try:
            host = self._get_radare_endpoint()
            response = requests.post(f'{host}/v1/retrieve', data=binary, verify=False)
            if response.status_code != 200:
                raise TimeoutError(response.text)
            target_link = f"{host}{response.json()['endpoint']}m/"
            sleep(1)
            return redirect(target_link)
        except (requests.exceptions.ConnectionError, TimeoutError, KeyError) as error:
            return render_template('error.html', message=str(error))

    @staticmethod
    def _get_radare_endpoint() -> str:
        radare2_host = cfg.expert_settings.radare2_host
        if cfg.expert_settings.nginx:
            return f'https://{radare2_host}/radare'
        return f'http://{radare2_host}:8000'

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/pdf-download/<uid>', GET)
    def download_pdf_report(self, uid):
        with get_shared_session(self.db.frontend) as frontend_db:
            object_exists = frontend_db.exists(uid)
            if not object_exists:
                return render_template('uid_not_found.html', uid=uid)

            firmware = frontend_db.get_complete_object_including_all_summaries(uid)

        try:
            with TemporaryDirectory(dir=cfg.data_storage.docker_mount_base_dir) as folder:
                pdf_path = build_pdf_report(firmware, Path(folder))
                binary = pdf_path.read_bytes()
        except RuntimeError as error:
            return render_template('error.html', message=str(error))

        response = make_response(binary)
        response.headers['Content-Disposition'] = f'attachment; filename={pdf_path.name}'

        return response

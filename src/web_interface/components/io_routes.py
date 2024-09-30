from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from time import sleep
from typing import TYPE_CHECKING
from zipfile import ZIP_DEFLATED, ZipFile

import requests
from flask import Response, make_response, redirect, render_template, request

import config
from helperFunctions import magic
from helperFunctions.database import get_shared_session
from helperFunctions.pdf import build_pdf_report
from helperFunctions.task_conversion import check_for_errors, convert_analysis_task_to_fw_obj, create_analysis_task
from storage.migration import get_current_revision
from web_interface.components.component_base import GET, POST, AppRoute, ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

if TYPE_CHECKING:
    from storage.db_interface_frontend import FrontEndDbInterface


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
        self.intercom.add_analysis_task(fw)
        return render_template('upload/upload_successful.html', uid=analysis_task['uid'])

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/upload', GET)
    def get_upload(self, error=None):
        error = error or {}
        with get_shared_session(self.db.frontend) as frontend_db:
            device_class_list = frontend_db.get_device_class_list()
            vendor_list = frontend_db.get_vendor_list()
            device_name_dict = frontend_db.get_device_name_dict()
        analysis_plugins = self.intercom.get_available_analysis_plugins()
        return render_template(
            'upload/upload.html',
            device_classes=device_class_list,
            vendors=vendor_list,
            error=error,
            analysis_presets=list(config.frontend.analysis_preset),
            device_names=json.dumps(device_name_dict, sort_keys=True),
            analysis_plugin_dict=analysis_plugins,
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

    def _prepare_file_download(self, uid: str, packed: bool = False) -> str | Response:
        if not self.db.frontend.exists(uid):
            return render_template('uid_not_found.html', uid=uid)
        if packed:
            result = self.intercom.get_repacked_binary_and_file_name(uid)
        else:
            result = self.intercom.get_binary_and_filename(uid)
        if result is None:
            return render_template('error.html', message='timeout')
        binary, file_name = result
        response = self._make_file_response(binary, file_name)
        response.headers['Content-Type'] = 'application/gzip' if packed else self._get_file_download_mime(binary, uid)
        return response

    def _get_file_download_mime(self, binary: bytes, uid: str) -> str:
        type_analysis = self.db.frontend.get_analysis(uid, 'file_type')
        mime = type_analysis.get('mime') if type_analysis is not None else None
        return mime or magic.from_buffer(binary, mime=True)

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/ida-download/<compare_id>', GET)
    def download_ida_file(self, compare_id):
        # FixMe: IDA comparison plugin must not add binary strings to the result (not JSON compatible)
        result = self.db.comparison.get_comparison_result(compare_id)
        if result is None:
            return render_template('error.html', message=f'Comparison with ID {compare_id} not found')
        binary = result['plugins']['Ida_Diff_Highlighting']['idb_binary']
        return self._make_file_response(binary, f'{compare_id[:8]}.idb')

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/radare-view/<uid>', GET)
    def show_radare(self, uid):
        object_exists = self.db.frontend.exists(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        result = self.intercom.get_binary_and_filename(uid)
        if result is None:
            return render_template('error.html', message='timeout')
        binary, _ = result
        try:
            host = config.frontend.radare2_url
            response = requests.post(f'{host}/v1/retrieve', data=binary, verify=False)
            if response.status_code != 200:  # noqa: PLR2004
                raise TimeoutError(response.text)
            target_link = f"{host}{response.json()['endpoint']}m/"
            sleep(1)
            return redirect(target_link)
        except (requests.exceptions.ConnectionError, TimeoutError, KeyError) as error:
            return render_template('error.html', message=str(error))

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/pdf-download/<uid>', GET)
    def download_pdf_report(self, uid):
        with get_shared_session(self.db.frontend) as frontend_db:
            object_exists = frontend_db.exists(uid)
            if not object_exists:
                return render_template('uid_not_found.html', uid=uid)

            firmware = frontend_db.get_complete_object_including_all_summaries(uid)

        try:
            with TemporaryDirectory(dir=config.frontend.docker_mount_base_dir) as folder:
                pdf_path = build_pdf_report(firmware, Path(folder))
                return self._make_file_response(pdf_path.read_bytes(), pdf_path.name)
        except RuntimeError as error:
            return render_template('error.html', message=str(error))

    @staticmethod
    def _make_file_response(content: bytes, file_name: str) -> Response:
        response = make_response(content)
        response.headers['Content-Disposition'] = f'attachment; filename={file_name}'
        return response

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/export/<string:uid>', GET)
    def export_firmware(self, uid: str):
        with get_shared_session(self.db.frontend) as frontend_db:
            if not frontend_db.is_firmware(uid):
                return render_template('uid_not_found.html', uid=uid)
            json_data = self._prepare_data_for_export(frontend_db, uid)

        zipped = self.intercom.get_zipped_files_from_fw(uid)
        with BytesIO(zipped) as buffer:
            with ZipFile(buffer, 'a', ZIP_DEFLATED) as zip_file:
                zip_file.writestr('data.json', json.dumps(json_data))
            return self._make_file_response(buffer.getvalue(), f'FACT_export_{uid}.zip')

    @staticmethod
    def _prepare_data_for_export(frontend_db: FrontEndDbInterface, uid: str) -> dict:
        all_files = frontend_db.get_all_files_in_fw(uid)
        return {
            'db_revision': get_current_revision(),
            'files': [
                fo.to_json(vfp_parent_filter=all_files.union(uid))
                for fo in frontend_db.get_objects_by_uid_list(all_files)
            ],
            'firmware': frontend_db.get_object(uid).to_json(),
            'uid': uid,
        }

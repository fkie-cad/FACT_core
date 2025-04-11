from __future__ import annotations

import http
import json
import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from time import sleep

import requests
from flask import Response, make_response, redirect, render_template, request
from werkzeug.exceptions import BadRequestKeyError

import config
from helperFunctions import magic
from helperFunctions.database import get_shared_session
from helperFunctions.pdf import build_pdf_report
from helperFunctions.task_conversion import convert_analysis_task_to_fw_obj, create_analysis_task
from web_interface.components.component_base import GET, POST, AppRoute, ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class IORoutes(ComponentBase):
    # ---- upload

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/upload', POST)
    def post_upload(self):
        try:
            analysis_task = create_analysis_task(request)
        except BadRequestKeyError as error:
            # we don't want this to fail silently; we want to know what's wrong with the request
            logging.warning(f'Received invalid upload request: Key {KeyError.__str__(error)} is missing!')
            raise
        fw = convert_analysis_task_to_fw_obj(analysis_task)
        self.intercom.add_analysis_task(fw)
        return render_template('upload/upload_successful.html', uid=analysis_task['uid'])

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @AppRoute('/upload', GET)
    def get_upload(self):
        with get_shared_session(self.db.frontend) as frontend_db:
            device_class_list = frontend_db.get_device_class_list()
            vendor_list = frontend_db.get_vendor_list()
            device_name_dict = frontend_db.get_device_name_dict()
        analysis_plugins = {
            k: t[:3] for k, t in self.intercom.get_available_analysis_plugins().items() if k != 'unpacker'
        }
        return render_template(
            'upload/upload.html',
            device_classes=device_class_list,
            vendors=vendor_list,
            analysis_presets=list(config.frontend.analysis_preset),
            device_names=json.dumps(device_name_dict, sort_keys=True),
            analysis_plugin_dict=analysis_plugins,
            selected_preset='default',
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
        with get_shared_session(self.db.frontend) as frontend_db:
            if not (frontend_db.exists(uid)):
                return render_template('uid_not_found.html', uid=uid)
            file_name = frontend_db.get_file_name(uid)
        if packed:
            contents = self.intercom.get_repacked_file(uid)
            file_name = f'{file_name}.tar.gz'
        else:
            contents = self.intercom.get_file_contents(uid)
        if contents is None:
            return render_template('error.html', message='timeout')
        if contents == b'':
            return render_template('error.html', message='file not found')
        response = make_response(contents)
        response.headers['Content-Disposition'] = f'attachment; filename={file_name}'
        response.headers['Content-Type'] = 'application/gzip' if packed else self._get_file_download_mime(contents, uid)
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
        response = make_response(binary)
        response.headers['Content-Disposition'] = f'attachment; filename={compare_id[:8]}.idb'
        return response

    @roles_accepted(*PRIVILEGES['download'])
    @AppRoute('/radare-view/<uid>', GET)
    def show_radare(self, uid):
        object_exists = self.db.frontend.exists(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        binary = self.intercom.get_file_contents(uid)
        if binary is None:
            return render_template('error.html', message='timeout')
        try:
            host = config.frontend.radare2_url
            response = requests.post(f'{host}/v1/retrieve', data=binary, verify=False)
            if response.status_code != http.HTTPStatus.OK:
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
                binary = pdf_path.read_bytes()
        except RuntimeError as error:
            return render_template('error.html', message=str(error))

        response = make_response(binary)
        response.headers['Content-Disposition'] = f'attachment; filename={pdf_path.name}'

        return response

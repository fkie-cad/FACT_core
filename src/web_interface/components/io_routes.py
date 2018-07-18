# -*- coding: utf-8 -*-

import binascii
import json
from time import sleep

import requests
from flask import request, render_template, make_response, redirect

from helperFunctions.dataConversion import remove_linebreaks_from_byte_string
from helperFunctions.mongo_task_conversion import create_analysis_task, check_for_errors, convert_analysis_task_to_fw_obj
from helperFunctions.web_interface import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.additional_functions.hex_dump import create_hex_dump
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class IORoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule('/upload', 'upload', self._app_upload, methods=['GET', 'POST'])
        self._app.add_url_rule('/download/<uid>', '/download/<uid>', self._app_download_binary)
        self._app.add_url_rule('/tar-download/<uid>', '/tar-download/<uid>', self._app_download_tar)
        self._app.add_url_rule('/ida-download/<compare_id>', 'ida-download/<compare_id>', self._download_ida_file)
        self._app.add_url_rule('/base64-download/<uid>/<section>/<expression_id>', '/base64-download/<uid>/<section>/<expression_id>', self._download_base64_decoded_section)
        self._app.add_url_rule('/hex-dump/<uid>', 'hex-dump/<uid>', self._show_hex_dump)
        self._app.add_url_rule('/radare/<uid>', 'radare/<uid>', self._show_radare)

    @roles_accepted(*PRIVILEGES['download'])
    def _download_base64_decoded_section(self, uid, section, expression_id):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            file_obj = sc.get_object(uid, analysis_filter=['base64_decoder'])
        span_in_binary, span_in_section = None, (None, None)
        for expression in file_obj.processed_analysis['base64_decoder'][section]:
            if expression['id'] == int(expression_id):
                span_in_section = expression['span_in_section']
                span_in_binary = expression['span_in_binary']
                break

        if not span_in_binary:
            return render_template('error.html', message='Undisclosed error in base64 decoding')

        with ConnectTo(InterComFrontEndBinding, self._config) as connection:
            raw_binary = connection.get_binary_and_filename(file_obj.uid)

        binary, _ = remove_linebreaks_from_byte_string(raw_binary[0][span_in_binary[0]:span_in_binary[1]])

        try:
            binary = binascii.a2b_base64(binary[span_in_section[0]:span_in_section[1]])
        except binascii.Error as error:
            return render_template('error.html', message=str(error))
        else:
            resp = make_response(binary)
            resp.headers['Content-Disposition'] = 'attachment; filename={}'.format(file_obj.file_name + '_0x%X' % (span_in_binary[0] + span_in_section[0]) + '-0x%X_decoded' % (span_in_binary[1] - span_in_section[2]))
            return resp

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
        return render_template('upload/upload.html', device_classes=device_class_list, vendors=vendor_list, error=error,
                               device_names=json.dumps(device_name_dict, sort_keys=True),
                               analysis_plugin_dict=analysis_plugins)

        # ---- file download

    @roles_accepted(*PRIVILEGES['download'])
    def _app_download_binary(self, uid):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        else:
            with ConnectTo(InterComFrontEndBinding, self._config) as sc:
                result = sc.get_binary_and_filename(uid)
            if result is None:
                return render_template('error.html', message='timeout')
            else:
                binary, file_name = result
                resp = make_response(binary)
                resp.headers['Content-Disposition'] = 'attachment; filename={}'.format(file_name)
                return resp

    @roles_accepted(*PRIVILEGES['download'])
    def _app_download_tar(self, uid):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        else:
            with ConnectTo(InterComFrontEndBinding, self._config) as sc:
                result = sc.get_repacked_binary_and_file_name(uid)
            if result is None:
                return render_template('error.html', message='timeout')
            else:
                binary, file_name = result
                resp = make_response(binary)
                resp.headers['Content-Disposition'] = 'attachment; filename={}'.format(file_name)
                return resp

    @roles_accepted(*PRIVILEGES['download'])
    def _download_ida_file(self, compare_id):
        with ConnectTo(CompareDbInterface, self._config) as sc:
            result = sc.get_compare_result(compare_id)
        if result is None:
            return render_template('error.html', message='timeout')
        elif isinstance(result, str):
            return render_template('error.html', message=result)
        else:
            binary = result['plugins']['Ida_Diff_Highlighting']['idb_binary']
            resp = make_response(binary)
            resp.headers['Content-Disposition'] = 'attachment; filename={}.idb'.format(compare_id[:8])
            return resp

    @roles_accepted(*PRIVILEGES['download'])
    def _show_hex_dump(self, uid):
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        else:
            with ConnectTo(InterComFrontEndBinding, self._config) as sc:
                result = sc.get_binary_and_filename(uid)
            if result is None:
                return render_template('error.html', message='timeout')
            else:
                binary, _ = result
                try:
                    hex_dump = create_hex_dump(binary)
                    return render_template('generic_view/hex_dump_popup.html', uid=uid, hex_dump=hex_dump)
                except Exception as exception:
                    return render_template('error.html', message=str(exception))

    @roles_accepted(*PRIVILEGES['download'])
    def _show_radare(self, uid):
        HOST, ENDPOINT = 'http://localhost/radare', '/v1/retrieve'
        with ConnectTo(FrontEndDbInterface, self._config) as sc:
            object_exists = sc.existence_quick_check(uid)
        if not object_exists:
            return render_template('uid_not_found.html', uid=uid)
        else:
            with ConnectTo(InterComFrontEndBinding, self._config) as sc:
                result = sc.get_binary_and_filename(uid)
            if result is None:
                return render_template('error.html', message='timeout')
            else:
                binary, _ = result
                try:
                    response = requests.post('{}{}'.format(HOST, ENDPOINT), data=binary)
                    if response.status_code == 200:
                        target_link = '{}{}enyo/'.format(HOST, response.json()['endpoint'])
                        sleep(1)
                        return redirect(target_link)
                    else:
                        raise TimeoutError(response.text)
                except Exception as exception:
                    return render_template('error.html', message=str(exception))

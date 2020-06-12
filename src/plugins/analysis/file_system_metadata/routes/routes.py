import os
from base64 import b64encode

from common_helper_files.fail_safe_file_operations import get_dir_of_file
from flask import render_template_string
from flask_restful import Resource

from helperFunctions.database import ConnectTo
from helperFunctions.rest import error_message, success_message
from objects.file import FileObject
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

from ..code.file_system_metadata import AnalysisPlugin, FsMetadataDbInterface


class FsMetadataRoutesDbInterface(FsMetadataDbInterface):

    def get_analysis_results_for_included_uid(self, uid: str):
        results = {}
        this_fo = self.get_object(uid)
        if this_fo is not None:
            parent_uids = self.get_parent_uids_from_virtual_path(this_fo)
            for current_uid in parent_uids:
                parent_fo = self.get_object(current_uid)
                self.get_results_from_parent_fos(parent_fo, this_fo, results)
        return results

    @staticmethod
    def get_results_from_parent_fos(parent_fo: FileObject, this_fo: FileObject, results: dict):
        if parent_fo is None:
            return None

        file_names = [
            virtual_file_path.split('|')[-1][1:]
            for virtual_path_list in this_fo.virtual_file_path.values()
            for virtual_file_path in virtual_path_list
            if parent_fo.uid in virtual_file_path
        ]

        if AnalysisPlugin.NAME in parent_fo.processed_analysis and 'files' in parent_fo.processed_analysis[AnalysisPlugin.NAME]:
            parent_analysis = parent_fo.processed_analysis[AnalysisPlugin.NAME]['files']
            for file_name in file_names:
                encoded_name = b64encode(file_name.encode()).decode()
                if encoded_name in parent_analysis:
                    results[file_name] = parent_analysis[encoded_name]
                    results[file_name]['parent_uid'] = parent_fo.uid
        return None


class PluginRoutes(ComponentBase):

    def _init_component(self):
        self._app.add_url_rule('/plugins/file_system_metadata/ajax/<uid>', 'plugins/file_system_metadata/ajax/<uid>', self._get_analysis_results_of_parent_fo)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _get_analysis_results_of_parent_fo(self, uid):
        with ConnectTo(FsMetadataRoutesDbInterface, self._config) as db:
            results = db.get_analysis_results_for_included_uid(uid)
        return render_template_string(self._load_view(), results=results)

    @staticmethod
    def _load_view():
        file_dir = get_dir_of_file(__file__)
        path = os.path.join(file_dir, 'ajax_view.html')
        with open(path, "r") as fp:
            return fp.read()


class FSMetadataRoutesRest(Resource):
    ENDPOINTS = [('/plugins/file_system_metadata/rest/<uid>', ['GET'])]

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self, uid):
        with ConnectTo(FsMetadataRoutesDbInterface, self.config) as db:
            results = db.get_analysis_results_for_included_uid(uid)
        endpoint = self.ENDPOINTS[0][0]
        if not results:
            error_message('no results found for uid {}'.format(uid), endpoint, request_data={'uid': uid})
        return success_message({AnalysisPlugin.NAME: results}, endpoint, request_data={'uid': uid})

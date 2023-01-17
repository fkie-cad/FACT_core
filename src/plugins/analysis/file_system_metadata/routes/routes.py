from __future__ import annotations

from base64 import b64encode
from pathlib import Path

from flask import render_template_string
from flask_restx import Namespace

from helperFunctions.database import get_shared_session
from objects.file import FileObject
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

from ..code.file_system_metadata import AnalysisPlugin

VIEW_PATH = Path(__file__).absolute().parent / 'ajax_view.html'


def get_analysis_results_for_included_uid(
    uid: str, db_interface: FrontEndDbInterface
) -> dict:  # pylint: disable=invalid-name
    results = {}
    with get_shared_session(db_interface) as db:
        this_fo = db.get_object(uid)
        if this_fo is not None:
            for parent_uid in this_fo.parents:
                parent_results = db.get_analysis(parent_uid, AnalysisPlugin.NAME)
                results.update(_get_results_from_parent_fo(parent_results, parent_uid, this_fo))
    return results


def _get_results_from_parent_fo(parent_results: dict | None, parent_uid: str, this_fo: FileObject) -> dict:
    if parent_results is None or 'files' not in parent_results:
        return {}

    results = {}
    for file_name in _get_parent_file_names(parent_uid, this_fo):
        encoded_name = b64encode(file_name.encode()).decode()
        if encoded_name in parent_results['files']:
            results[file_name] = parent_results['files'][encoded_name]
            results[file_name]['parent_uid'] = parent_uid
    return results


def _get_parent_file_names(parent_uid, this_fo):
    return [
        virtual_file_path.split('|')[-1][1:]
        for virtual_path_list in this_fo.virtual_file_path.values()
        for virtual_file_path in virtual_path_list
        if parent_uid in virtual_file_path
    ]


class PluginRoutes(ComponentBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def _init_component(self):
        self._app.add_url_rule(
            '/plugins/file_system_metadata/ajax/<uid>',
            'plugins/file_system_metadata/ajax/<uid>',
            self._get_analysis_results_of_parent_fo,
        )

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _get_analysis_results_of_parent_fo(self, uid):
        results = get_analysis_results_for_included_uid(uid, self.db.frontend)
        return render_template_string(VIEW_PATH.read_text(), results=results)


api = Namespace('/plugins/file_system_metadata/rest')


@api.hide
class FSMetadataRoutesRest(RestResourceBase):
    ENDPOINTS = [('/plugins/file_system_metadata/rest/<uid>', ['GET'])]

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self, uid):
        results = get_analysis_results_for_included_uid(uid, self.db.frontend)
        endpoint = self.ENDPOINTS[0][0]
        if not results:
            error_message(f'no results found for uid {uid}', endpoint, request_data={'uid': uid})
        return success_message({AnalysisPlugin.NAME: results}, endpoint, request_data={'uid': uid})

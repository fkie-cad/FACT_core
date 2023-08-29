from pathlib import Path

from flask import render_template_string
from flask_restx import Namespace

from helperFunctions.database import get_shared_session
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

from ..code.qemu_exec import AnalysisPlugin

VIEW_PATH = Path(__file__).absolute().parent / 'ajax_view.html'


def get_analysis_results_for_included_uid(uid: str, db_interface: FrontEndDbInterface):
    results = {}
    with get_shared_session(db_interface) as db:
        this_fo = db.get_object(uid)
        if this_fo is not None:
            for parent_uid in this_fo.parents:
                parent_results = _get_results_from_parent_fo(db.get_analysis(parent_uid, AnalysisPlugin.NAME), uid)
                if parent_results:
                    results[parent_uid] = parent_results
    return results


def _get_results_from_parent_fo(analysis_entry: dict, uid: str):
    if analysis_entry is not None and 'files' in analysis_entry and uid in analysis_entry['files']:
        return analysis_entry['files'][uid]
    return None


class PluginRoutes(ComponentBase):
    def _init_component(self):
        self._app.add_url_rule(
            '/plugins/qemu_exec/ajax/<uid>', 'plugins/qemu_exec/ajax/<uid>', self._get_analysis_results_of_parent_fo
        )

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _get_analysis_results_of_parent_fo(self, uid):
        results = get_analysis_results_for_included_uid(uid, self.db.frontend)
        return render_template_string(VIEW_PATH.read_text(), results=results)


api = Namespace('/plugins/qemu_exec/rest')


@api.hide
class PluginRestRoutes(RestResourceBase):
    ENDPOINTS = (('/plugins/qemu_exec/rest/<uid>', ['GET']),)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self, uid):
        results = get_analysis_results_for_included_uid(uid, self.db.frontend)
        endpoint = self.ENDPOINTS[0][0]
        if not results:
            error_message(f'no results found for uid {uid}', endpoint, request_data={'uid': uid})
        return success_message({AnalysisPlugin.NAME: results}, endpoint, request_data={'uid': uid})

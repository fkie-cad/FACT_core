from pathlib import Path

from flask import render_template_string
from flask_restx import Namespace, Resource

from helperFunctions.virtual_file_path import get_parent_uids_from_virtual_path
from storage_postgresql.db_interface_frontend import FrontEndDbInterface
from storage_postgresql.schema import AnalysisEntry
from web_interface.components.component_base import ComponentBase
from web_interface.rest.helper import error_message, success_message
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

from ..code.qemu_exec import AnalysisPlugin

VIEW_PATH = Path(__name__).parent.parent / 'routes' / 'ajax_view.html'


def get_analysis_results_for_included_uid(uid: str, db: FrontEndDbInterface):  # pylint: disable=invalid-name
    results = {}
    this_fo = db.get_object(uid)
    if this_fo is not None:
        for parent_uid in get_parent_uids_from_virtual_path(this_fo):
            parent_results = _get_results_from_parent_fo(db.get_analysis(uid, AnalysisPlugin.NAME), uid)
            if parent_results:
                results[parent_uid] = parent_results
    return results


def _get_results_from_parent_fo(analysis_entry: AnalysisEntry, uid: str):
    if (
        analysis_entry is not None
        and 'files' in analysis_entry.result
        and uid in analysis_entry.result['files']
    ):
        return analysis_entry.result['files'][uid]
    return None


class PluginRoutes(ComponentBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.db = FrontEndDbInterface(config=self._config)

    def _init_component(self):
        self._app.add_url_rule('/plugins/qemu_exec/ajax/<uid>', 'plugins/qemu_exec/ajax/<uid>', self._get_analysis_results_of_parent_fo)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _get_analysis_results_of_parent_fo(self, uid):
        results = get_analysis_results_for_included_uid(uid, self.db)
        return render_template_string(VIEW_PATH.read_text(), results=results)


api = Namespace('/plugins/qemu_exec/rest')


@api.hide
class QemuExecRoutesRest(Resource):
    ENDPOINTS = [('/plugins/qemu_exec/rest/<uid>', ['GET'])]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = kwargs.get('config', None)
        self.db = FrontEndDbInterface(config=self.config)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self, uid):
        results = get_analysis_results_for_included_uid(uid, self.db)
        endpoint = self.ENDPOINTS[0][0]
        if not results:
            error_message('no results found for uid {}'.format(uid), endpoint, request_data={'uid': uid})
        return success_message({AnalysisPlugin.NAME: results}, endpoint, request_data={'uid': uid})

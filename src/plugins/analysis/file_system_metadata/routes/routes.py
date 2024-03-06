from __future__ import annotations

from base64 import b64encode
from pathlib import Path
from typing import TYPE_CHECKING

from flask import render_template_string
from flask_restx import Namespace

from helperFunctions.database import get_shared_session
from web_interface.components.component_base import ComponentBase
from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

from ..code.file_system_metadata import AnalysisPlugin

if TYPE_CHECKING:
    from web_interface.frontend_database import FrontendDatabase


VIEW_PATH = Path(__file__).absolute().parent / 'ajax_view.html'


class ParentAnalysisLookupMixin:
    db: FrontendDatabase

    def get_analysis_results_for_included_uid(self, uid: str) -> dict:
        results = {}
        with get_shared_session(self.db.frontend) as db:
            vfp = db.get_vfps(uid)
            for parent_uid in vfp:
                parent_analysis = db.get_analysis(parent_uid, AnalysisPlugin.NAME) or {}
                results.update(_get_results_from_parent_fo(parent_analysis.get('result', {}), parent_uid, vfp))
        return results


def _get_results_from_parent_fo(parent_results: dict | None, parent_uid: str, vfp: dict[str, list[str]]) -> dict:
    if parent_results is None or 'files' not in parent_results:
        return {}
    results_by_file = _result_list_to_dict(parent_results['files'])

    results = {}
    for file_name in vfp.get(parent_uid, []):
        key = file_name.lstrip('/')
        encoded_key = b64encode(key.encode()).decode()
        if encoded_key in results_by_file:
            results[key] = results_by_file[encoded_key]
            results[key]['parent_uid'] = parent_uid
    return results


def _result_list_to_dict(results: list[dict]) -> dict[str, dict]:
    return {metadata['key']: metadata for metadata in results}


class PluginRoutes(ComponentBase, ParentAnalysisLookupMixin):
    def _init_component(self):
        self._app.add_url_rule(
            '/plugins/file_system_metadata/ajax/<uid>',
            'plugins/file_system_metadata/ajax/<uid>',
            self._get_analysis_results_of_parent_fo,
        )
        assert VIEW_PATH.is_file()

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _get_analysis_results_of_parent_fo(self, uid):
        results = self.get_analysis_results_for_included_uid(uid)
        return render_template_string(VIEW_PATH.read_text(), results=results)


api = Namespace('/plugins/file_system_metadata/rest')


@api.hide
class PluginRestRoutes(RestResourceBase, ParentAnalysisLookupMixin):
    ENDPOINTS = (('/plugins/file_system_metadata/rest/<uid>', ['GET']),)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self, uid: str):
        results = self.get_analysis_results_for_included_uid(uid)
        endpoint = self.ENDPOINTS[0][0]
        if not results:
            error_message(f'no results found for uid {uid}', endpoint, request_data={'uid': uid})
        return success_message({AnalysisPlugin.NAME: results}, endpoint, request_data={'uid': uid})

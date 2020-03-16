import os
from contextlib import suppress

from flask import render_template_string
from flask_restful import Resource

from helperFunctions.database import ConnectTo
from helperFunctions.fileSystem import get_src_dir
from helperFunctions.rest import error_message, success_message
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.components.component_base import ComponentBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

from ..code.qemu_exec import AnalysisPlugin


def get_analysis_results_for_included_uid(uid, config):
    results = {}
    with ConnectTo(FrontEndDbInterface, config) as db:
        this_fo = db.get_object(uid)
        if this_fo is not None:
            for parent_uid in _get_parent_uids_from_virtual_path(this_fo):
                parent_fo = db.get_object(parent_uid)
                parent_results = _get_results_from_parent_fo(parent_fo, uid)
                if parent_results:
                    results[parent_uid] = parent_results
    return results


def _get_parent_uids_from_virtual_path(file_object):
    result = set()
    for path_list in file_object.virtual_file_path.values():
        for virtual_path in path_list:
            with suppress(IndexError):
                result.add(virtual_path.split("|")[-2])
    return result


def _get_results_from_parent_fo(parent_fo, uid):
    if parent_fo is not None and \
            AnalysisPlugin.NAME in parent_fo.processed_analysis and \
            'files' in parent_fo.processed_analysis[AnalysisPlugin.NAME] and \
            uid in parent_fo.processed_analysis[AnalysisPlugin.NAME]['files']:
        return parent_fo.processed_analysis[AnalysisPlugin.NAME]['files'][uid]
    return None


class PluginRoutes(ComponentBase):

    def _init_component(self):
        self._app.add_url_rule('/plugins/qemu_exec/ajax/<uid>', 'plugins/qemu_exec/ajax/<uid>', self._get_analysis_results_of_parent_fo)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def _get_analysis_results_of_parent_fo(self, uid):
        results = get_analysis_results_for_included_uid(uid, self._config)
        return render_template_string(self._load_view(), results=results)

    @staticmethod
    def _load_view():
        path = os.path.join(get_src_dir(), 'plugins/analysis/{}/routes/ajax_view.html'.format(AnalysisPlugin.NAME))
        with open(path, "r") as fp:
            return fp.read()


class QemuExecRoutesRest(Resource):
    ENDPOINTS = [('/plugins/qemu_exec/rest/<uid>', ['GET'])]

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self, uid):
        results = get_analysis_results_for_included_uid(uid, self.config)
        endpoint = self.ENDPOINTS[0][0]
        if not results:
            error_message('no results found for uid {}'.format(uid), endpoint, request_data={'uid': uid})
        return success_message({AnalysisPlugin.NAME: results}, endpoint, request_data={'uid': uid})

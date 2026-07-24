from __future__ import annotations

from http import HTTPStatus

from flask import request
from flask_restx import Namespace

from web_interface.rest.helper import error_message, get_boolean_from_request, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/analysis', description='Request the analysis results of a specific plugin for a file')


@api.route(
    '/<string:uid>/<string:plugin>',
    doc={
        'description': '',
        'params': {
            'uid': 'File UID',
            'plugin': 'The name of the analysis plugin (lower case with underscores, e.g. file_type)',
            'force': {
                'description': 'Force re-analysis of already analyzed files',
                'in': 'query',
                'type': 'boolean',
                'default': 'false',
            },
            'recursive_summary': {
                'description': 'Include summary of included files for requested analysis result',
                'in': 'query',
                'type': 'boolean',
                'default': 'false',
            },
        },
    },
)
class RestAnalysis(RestResourceBase):
    URL = '/rest/analysis'

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @api.doc(
        responses={
            HTTPStatus.OK: 'Success',
            HTTPStatus.BAD_REQUEST: 'Unknown file object',
            HTTPStatus.PRECONDITION_FAILED: 'Unknown plugin or analysis did not run (yet)',
        }
    )
    def get(self, uid: str, plugin: str) -> tuple[dict, int]:
        """
        Get the analysis results of a specific plugin for a specific file.
        """
        skip_summary = 'summary' not in request.args or not get_boolean_from_request(request.args, 'recursive_summary')
        if skip_summary:
            analysis = self.db.frontend.get_analysis(uid, plugin)
            recursive_summary = []
        else:
            fo = self.db.frontend.get_object(
                uid,
                analysis_filter=[
                    plugin,
                ],
            )
            analysis = fo.processed_analysis[plugin] if fo else []
            recursive_summary = self.db.frontend.get_summary(fo, plugin) if fo else []

        request_data = {'uid': uid, 'plugin': plugin}

        if not analysis:
            if not self.db.frontend.exists(uid):
                message = f'No file object with UID "{uid}" found'
                return_code = HTTPStatus.BAD_REQUEST
            else:
                message = f'Analysis "{plugin}" not found for file "{uid}"'
                return_code = HTTPStatus.PRECONDITION_FAILED
            return error_message(message, self.URL, request_data, return_code=return_code)

        return success_message({'analysis': analysis, 'recursive_summary': recursive_summary}, self.URL, request_data)

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @api.doc(
        responses={
            HTTPStatus.OK: 'Success',
            HTTPStatus.BAD_REQUEST: 'Unknown file object or plugin',
        }
    )
    def put(self, uid: str, plugin: str) -> tuple[dict, int]:
        """
        Run a specific analysis on a specific file.
        """
        file_object = self.db.frontend.get_object(uid)
        request_data = {'uid': uid, 'plugin': plugin}

        if not file_object:
            message = f'No file object with UID "{uid}" found'
            return error_message(message, self.URL, request_data, return_code=HTTPStatus.BAD_REQUEST)

        available_plugins = self.intercom.get_available_analysis_plugins()
        if plugin not in available_plugins:
            message = f'Analysis plugin "{plugin}" not found'
            return error_message(message, self.URL, request_data, return_code=HTTPStatus.BAD_REQUEST)

        file_object.scheduled_analysis = [plugin]
        if 'force' in request.args:
            force_flag = get_boolean_from_request(request.args, 'force')
            file_object.force_update = force_flag
        success = self.intercom.add_single_file_task(file_object)

        if success:
            return success_message({'success': True}, self.URL, request_data)
        return error_message('Failed to schedule analysis', self.URL, request_data, return_code=HTTPStatus.BAD_REQUEST)

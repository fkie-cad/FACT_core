from __future__ import annotations

from http import HTTPStatus

from flask_restx import Namespace

from web_interface.rest.helper import error_message, success_message
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
        analysis = self.db.frontend.get_analysis(uid, plugin)
        request_data = {'uid': uid, 'plugin': plugin}

        if not analysis:
            if not self.db.frontend.exists(uid):
                message = f'No file object with UID "{uid}" found'
                return_code = HTTPStatus.BAD_REQUEST
            else:
                message = f'Analysis "{plugin}" not found for file "{uid}"'
                return_code = HTTPStatus.PRECONDITION_FAILED
            return error_message(message, self.URL, request_data, return_code=return_code)

        return success_message({'analysis': analysis}, self.URL, request_data)

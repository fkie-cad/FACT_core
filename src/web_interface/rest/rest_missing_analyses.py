from __future__ import annotations

from flask_restx import Namespace

from helperFunctions.database import get_shared_session
from web_interface.rest.helper import success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/missing', description='Search the database for missing entries')


@api.route('')
class RestMissingAnalyses(RestResourceBase):
    URL = '/rest/missing'

    @roles_accepted(*PRIVILEGES['delete'])
    @api.doc(responses={200: 'Success', 400: 'Unknown'})
    def get(self):
        '''
        Search for missing files or missing analyses
        Search for missing or orphaned files and missing or failed analyses
        '''
        with get_shared_session(self.db.frontend) as frontend_db:
            missing_analyses_data = {
                'missing_analyses': self._make_json_serializable(frontend_db.find_missing_analyses()),
                'failed_analyses': self._make_json_serializable(frontend_db.find_failed_analyses()),
            }
        return success_message(missing_analyses_data, self.URL)

    @staticmethod
    def _make_json_serializable(set_dict: dict[str, set[str]]) -> dict[str, list[str]]:
        return {k: list(v) for k, v in set_dict.items()}

from flask import request
from flask_restx import Namespace

from helperFunctions.object_conversion import create_meta_dict
from storage.db_interface_base import DbInterfaceError
from web_interface.rest.helper import error_message, get_paging, get_query, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/file_object', description='Browse the file database or request specific file')


@api.route('', doc={'description': 'Browse the file database'})
class RestFileObjectWithoutUid(RestResourceBase):
    URL = '/rest/file_object'

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @api.doc(
        responses={200: 'Success', 400: 'Error'},
        params={
            'offset': {'description': 'offset of results (paging)', 'in': 'query', 'type': 'int'},
            'limit': {'description': 'number of results (paging)', 'in': 'query', 'type': 'int'},
            'query': {'description': 'MongoDB style query', 'in': 'query', 'type': 'dict'},
        },
    )
    def get(self):
        """
        Browse the file database
        """
        try:
            query = get_query(request.args)
            offset, limit = get_paging(request.args)
        except ValueError as value_error:
            request_data = {k: request.args.get(k) for k in ['query', 'limit', 'offset']}
            return error_message(str(value_error), self.URL, request_data=request_data)

        parameters = {'offset': offset, 'limit': limit, 'query': query}
        try:
            uids = self.db.frontend.rest_get_file_object_uids(offset, limit, query)
            return success_message({'uids': uids}, self.URL, parameters)
        except DbInterfaceError:
            return error_message('Unknown exception on request', self.URL, parameters)


@api.route(
    '/<string:uid>',
    doc={
        'description': 'Request specific file by providing the uid of the corresponding object',
        'params': {
            'uid': 'File UID',
            'summary': {
                'description': 'include summary in result',
                'in': 'query',
                'type': 'boolean',
                'default': 'false',
            },
        },
    },
)
class RestFileObjectWithUid(RestResourceBase):
    URL = '/rest/file_object'

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @api.doc(responses={200: 'Success', 400: 'Unknown file object'})
    def get(self, uid):
        """
        Request a specific file
        Get the analysis results of a specific file by providing the corresponding uid
        """
        file_object = self.db.frontend.get_object(uid)
        if not file_object:
            return error_message(f'No file object with UID {uid} found', self.URL, {'uid': uid})

        fitted_file_object = self._fit_file_object(file_object)
        return success_message({'file_object': fitted_file_object}, self.URL, request_data={'uid': uid})

    @staticmethod
    def _fit_file_object(file_object):
        meta = create_meta_dict(file_object)
        analysis = file_object.processed_analysis
        return {'meta_data': meta, 'analysis': analysis}

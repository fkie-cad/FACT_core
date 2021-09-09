from flask import request
from flask_restx import Namespace
from pymongo.errors import PyMongoError

from helperFunctions.database import ConnectTo
from helperFunctions.object_conversion import create_meta_dict
from storage.db_interface_frontend import FrontEndDbInterface
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
            'query': {'description': 'MongoDB style query', 'in': 'query', 'type': 'dict'}
        }
    )
    def get(self):
        '''
        Browse the file database
        '''
        try:
            query = get_query(request.args)
            offset, limit = get_paging(request.args)
        except ValueError as value_error:
            request_data = {k: request.args.get(k) for k in ['query', 'limit', 'offset']}
            return error_message(str(value_error), self.URL, request_data=request_data)

        parameters = dict(offset=offset, limit=limit, query=query)
        try:
            with ConnectTo(FrontEndDbInterface, self.config) as connection:
                uids = connection.rest_get_file_object_uids(**parameters)
            return success_message(dict(uids=uids), self.URL, parameters)
        except PyMongoError:
            return error_message('Unknown exception on request', self.URL, parameters)


@api.route(
    '/<string:uid>',
    doc={
        'description': 'Request specific file by providing the uid of the corresponding object',
        'params': {
            'uid': 'File UID',
            'summary': {'description': 'include summary in result', 'in': 'query', 'type': 'boolean', 'default': 'false'}
        }
    }
)
class RestFileObjectWithUid(RestResourceBase):
    URL = '/rest/file_object'

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @api.doc(responses={200: 'Success', 400: 'Unknown file object'})
    def get(self, uid):
        '''
        Request a specific file
        Get the analysis results of a specific file by providing the corresponding uid
        '''
        with ConnectTo(FrontEndDbInterface, self.config) as connection:
            file_object = connection.get_file_object(uid)
        if not file_object:
            return error_message('No file object with UID {} found'.format(uid), self.URL, dict(uid=uid))

        fitted_file_object = self._fit_file_object(file_object)
        return success_message(dict(file_object=fitted_file_object), self.URL, request_data=dict(uid=uid))

    @staticmethod
    def _fit_file_object(file_object):
        meta = create_meta_dict(file_object)
        analysis = file_object.processed_analysis
        return dict(meta_data=meta, analysis=analysis)

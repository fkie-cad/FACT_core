from flask_restful import Resource, request
from pymongo.errors import PyMongoError

from helperFunctions.database import ConnectTo
from helperFunctions.object_conversion import create_meta_dict
from helperFunctions.rest import error_message, get_paging, get_query, success_message
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class RestFileObject(Resource):
    URL = '/rest/file_object'

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['view_analysis'])
    def get(self, uid=None):
        if not uid:
            return self._get_without_uid()
        return self._get_with_uid(uid)

    @staticmethod
    def _fit_file_object(file_object):
        meta = create_meta_dict(file_object)
        analysis = file_object.processed_analysis
        return dict(meta_data=meta, analysis=analysis)

    def _get_without_uid(self):
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

    def _get_with_uid(self, uid):
        with ConnectTo(FrontEndDbInterface, self.config) as connection:
            file_object = connection.get_file_object(uid)
        if not file_object:
            return error_message('No file object with UID {} found'.format(uid), self.URL, dict(uid=uid))

        fitted_file_object = self._fit_file_object(file_object)
        return success_message(dict(file_object=fitted_file_object), self.URL, request_data=dict(uid=uid))

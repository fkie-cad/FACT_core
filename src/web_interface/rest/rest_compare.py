from contextlib import suppress

from flask import request
from flask_restful import Resource

from helperFunctions.database import ConnectTo
from helperFunctions.dataConversion import normalize_compare_id
from helperFunctions.rest import convert_rest_request, error_message, success_message
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface, FactCompareException
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class RestCompare(Resource):
    URL = '/rest/compare'

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['compare'])
    def put(self):
        '''
        The request data should have the form
        {"uid_list": uid_list, "<optional>redo": True}
        return value: the result dict from the compare
        '''
        try:
            data = convert_rest_request(request.data)
        except TypeError as type_error:
            return error_message(str(type_error), self.URL, request_data=request.data)

        try:
            uid_string = ';'.join(data['uid_list'])
            compare_id = normalize_compare_id(uid_string)
            redo = data.get('redo', False)
        except (AttributeError, TypeError, KeyError):
            return error_message('Request should be of the form {"uid_list": uid_list, "redo": boolean}', self.URL, request_data=data)

        with ConnectTo(CompareDbInterface, self.config) as db_compare_service:
            if not db_compare_service.compare_result_is_in_db(compare_id) or redo:
                return self.start_compare(db_compare_service, compare_id, data, redo)
        return error_message('Compare already exists. Use "redo" to force re-compare.', self.URL, request_data=data, return_code=200)

    def start_compare(self, db_compare_service, compare_id, data, redo):
        try:
            db_compare_service.check_objects_exist(compare_id)
        except FactCompareException as exception:
            return error_message(exception.get_message(), self.URL, request_data=data, return_code=404)
        with ConnectTo(InterComFrontEndBinding, self.config) as intercom:
            intercom.add_compare_task(compare_id, force=redo)
        return success_message({'message': 'Compare started. Please use GET to get the results.'}, self.URL, request_data=data, return_code=202)

    @roles_accepted(*PRIVILEGES['compare'])
    def get(self, compare_id=None):
        '''
        The request data should have the form
        {"uid_list": uid_list, "<optional>redo": True}
        return value: the result dict from the compare
        '''
        try:
            compare_id = normalize_compare_id(compare_id)
        except (AttributeError, TypeError):
            return error_message('Compare ID must be of the form uid1;uid2(;uid3..)', self.URL, request_data={'compare_id': compare_id})

        with ConnectTo(CompareDbInterface, self.config) as db_compare_service:
            result = None
            with suppress(FactCompareException):
                if db_compare_service.compare_result_is_in_db(compare_id):
                    result = db_compare_service.get_compare_result(compare_id)
        if result:
            return success_message(result, self.URL, request_data={'compare_id': compare_id}, return_code=202)
        return error_message('Compare not found in database. Please use /rest/start_compare to start the compare.', self.URL, request_data={'compare_id': compare_id}, return_code=404)

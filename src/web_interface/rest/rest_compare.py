from flask import request
from flask_restful import Resource

from helperFunctions.dataConversion import unify_string_list
from helperFunctions.rest import success_message, error_message, convert_rest_request
from helperFunctions.web_interface import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface


class RestCompare(Resource):
    URL = '/rest/compare'

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

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
            compare_id = unify_string_list(uid_string)
            if 'redo' in data.keys():
                redo = data['redo']
            else:
                redo = False
        except Exception:  # FIXME Please specify Exception types - would think at least TypeError might occur
            return error_message('Request should be of the form {"uid_list": uid_list, "redo": boolean}', self.URL, request_data=data)

        with ConnectTo(CompareDbInterface, self.config) as db_compare_service:
            if not db_compare_service.compare_result_is_in_db(compare_id) or redo:
                err = db_compare_service.object_existence_quick_check(compare_id)
                if err is not None:
                    return error_message(err, self.URL, request_data=data, return_code=404)
                with ConnectTo(InterComFrontEndBinding, self.config) as intercom:
                    intercom.add_compare_task(compare_id, force=redo)
                return success_message({'message': 'Compare started. Please use GET to get the results.'}, self.URL, request_data=data, return_code=202)
        return error_message('Compare already exists. Use "redo" to force re-compare.', self.URL, request_data=data, return_code=200)

    def get(self, compare_id=None):
        '''
        The request data should have the form
        {"uid_list": uid_list, "<optional>redo": True}
        return value: the result dict from the compare
        '''
        try:
            compare_id = unify_string_list(compare_id)
        except Exception:  # FIXME Please specify Exception types - would think at least TypeError might occur
            return error_message('Compare ID must be of the form uid1;uid2(;uid3..)', self.URL, request_data={'compare_id': compare_id})

        with ConnectTo(CompareDbInterface, self.config) as db_compare_service:
            result = None
            if db_compare_service.compare_result_is_in_db(compare_id):
                result = db_compare_service.get_compare_result(compare_id)
        if result:
            return success_message(result, self.URL, request_data={'compare_id': compare_id}, return_code=202)
        else:
            return error_message('Compare not found in database. Please use /rest/start_compare to start the compare.', self.URL, request_data={'compare_id': compare_id}, return_code=404)

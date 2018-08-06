from flask_restful import Resource, request

from helperFunctions.rest import success_message, error_message, convert_rest_request
from helperFunctions.web_interface import ConnectTo
from helperFunctions.yara_binary_search import is_valid_yara_rule_file
from intercom.front_end_binding import InterComFrontEndBinding
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class RestBinarySearch(Resource):
    URL = '/rest/binary_search'

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(*PRIVILEGES['pattern_search'])
    def post(self):
        '''
        The request data should have the form
        {"rule_file": rule_file, 'uid': firmware_uid}
        The uid parameter is optional and can be specified if the user want's to search in the files of a single firmware.
        '''
        try:
            data = convert_rest_request(request.data)
        except TypeError as type_error:
            return error_message(str(type_error), self.URL, request_data=request.data)

        if 'rule_file' not in data:
            return error_message('rule_file could not be found in the request data', self.URL)

        if isinstance(data['rule_file'], str):
            data['rule_file'] = data['rule_file'].encode()

        if not is_valid_yara_rule_file(data['rule_file']):
            return error_message('Error in YARA rule file', self.URL, request_data=request.data)

        uid = None
        if 'uid' in data:
            if not self._firmware_is_in_db(data['uid']):
                error_str = 'Firmware with UID {uid} not found in database'.format(uid=data['uid'])
                return error_message(error_str, self.URL)
            uid = data['uid']

        with ConnectTo(InterComFrontEndBinding, self.config) as intercom:
            search_id = intercom.add_binary_search_request(data['rule_file'], uid)

        return success_message(
            {'message': 'Started binary search. Please use GET and the search_id to get the results'},
            self.URL,
            request_data={'search_id': search_id}
        )

    @roles_accepted(*PRIVILEGES['pattern_search'])
    def get(self, search_id=None):
        '''
        The search_id is needed to fetch the corresponding search result.
        The result of the search request can only be fetched once. After this the search needs to be started again.
        The results have the form:
        {'binary_search_results': {'<rule_name_1>': ['<matching_uid_1>', ...], '<rule_name_2>': [...], ...}
        '''

        if search_id is None:
            return error_message('The search_id is needed to fetch the search result', self.URL)

        with ConnectTo(InterComFrontEndBinding, self.config) as intercom:
            result, rule = intercom.get_binary_search_result(search_id)

        if result is None:
            return error_message('The result is not ready yet or it has already been fetched', self.URL)

        return success_message({'binary_search_results': result}, self.URL)

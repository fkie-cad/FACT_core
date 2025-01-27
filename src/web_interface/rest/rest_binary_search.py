from flask import request
from flask_restx import Namespace, fields

from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace(
    'rest/binary_search', description='Initiate a binary search on the binary database and fetch the results'
)

binary_search_model = api.model(
    'Binary Search',
    {
        'rule_file': fields.String(description='YARA rules', required=True),
        'uid': fields.String(description='Firmware UID (optional)'),
    },
    description='Expected value',
)


@api.route('', doc={'description': 'Binary search on all files in the database (or files of a single firmware)'})
class RestBinarySearchPost(RestResourceBase):
    URL = '/rest/binary_search'

    @roles_accepted(*PRIVILEGES['pattern_search'])
    @api.expect(binary_search_model)
    def post(self):
        """
        Start a binary search
        The parameter `uid` is optional and can be specified if the user wants to search the files of a single firmware
        `rule_file` can be something like `rule rule_name {strings: $a = \"foobar\" condition: $a}`
        """
        payload_data = self.validate_payload_data(binary_search_model)
        yara_error = self.intercom.get_yara_error(payload_data['rule_file'])
        if yara_error:
            return error_message(f'Error in YARA rule file: {yara_error}', self.URL, request_data=request.data)
        if payload_data['uid'] and not self.db.frontend.is_firmware(payload_data['uid']):
            return error_message(
                f'Firmware with UID {payload_data["uid"]} not found in database', self.URL, request_data=request.data
            )

        search_id = self.intercom.add_binary_search_request(payload_data['rule_file'].encode(), payload_data['uid'])

        return success_message(
            {'message': 'Started binary search. Please use GET and the search_id to get the results'},
            self.URL,
            request_data={'search_id': search_id},
        )


@api.route(
    '/<string:search_id>',
    doc={
        'description': 'Get the results of a previously initiated binary search',
        'params': {'search_id': 'Search ID'},
    },
)
class RestBinarySearchGet(RestResourceBase):
    URL = '/rest/binary_search'

    @roles_accepted(*PRIVILEGES['pattern_search'])
    @api.doc(responses={200: 'Success', 400: 'Unknown search ID'})
    def get(self, search_id=None):
        """
        Get the results of a previously initiated binary search
        The `search_id` is needed to fetch the corresponding search result
        The result of the search request can only be fetched once
        After this the search needs to be started again.
        """
        result, _ = self.intercom.get_binary_search_result(search_id)

        if result is None:
            return error_message('The result is not ready yet or it has already been fetched', self.URL)

        # the "new" binary search result has the structure {<uid>: {<rule>: [<str_match_data>]}}
        # we convert it back to the "old" structure {<rule>: [<uid>]} in order to maintain compatibility
        transposed_result = {}
        for uid, uid_result in result.items():
            for rule in uid_result:
                transposed_result.setdefault(rule, []).append(uid)

        return success_message({'binary_search_results': transposed_result}, self.URL)

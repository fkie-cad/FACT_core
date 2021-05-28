from flask import request
from flask_restx import Namespace, Resource, reqparse

from helperFunctions.database import ConnectTo
from helperFunctions.yara_binary_search import is_valid_yara_rule_file
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_frontend import FrontEndDbInterface
from web_interface.rest.helper import error_message, success_message
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES


class RestBinarySearchException(Exception):
    def get_message(self):
        return ", ".join(self.args)


api = Namespace('rest/binary_search', description='Initiate a binary search on the binary database and fetch the results')

post_arguments = reqparse.RequestParser(bundle_errors=True)
post_arguments.add_argument('rule_file', type=str, required=True, help='YARA rules', location='json')
post_arguments.add_argument('uid', type=str, help='optional Firmware UID', location='json', default=None)


class RestBinarySearchBase(Resource):
    URL = '/rest/binary_search'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = kwargs.get('config', None)


@api.route('', doc={'description': 'Binary search on all files in the database (or files of a single firmware)'})
class RestBinarySearchPost(RestBinarySearchBase):

    @roles_accepted(*PRIVILEGES['pattern_search'])
    @api.expect(post_arguments)
    def post(self):
        '''
        Start a binary search
        The parameter `uid` is optional and can be specified if the user wants to search the files of a single firmware
        `rule_file` can be something like `rule rule_name {strings: $a = \"foobar\" condition: $a}`
        '''
        args = post_arguments.parse_args()
        if not is_valid_yara_rule_file(args.rule_file):
            return error_message('Error in YARA rule file', self.URL, request_data=request.data)
        if args.uid and not self._is_firmware(args.uid):
            return error_message(
                f'Firmware with UID {args.uid} not found in database',
                self.URL, request_data=request.data
            )

        with ConnectTo(InterComFrontEndBinding, self.config) as intercom:
            search_id = intercom.add_binary_search_request(args.rule_file.encode(), args.uid)

        return success_message(
            {'message': 'Started binary search. Please use GET and the search_id to get the results'},
            self.URL,
            request_data={'search_id': search_id}
        )

    def _is_firmware(self, uid: str):
        with ConnectTo(FrontEndDbInterface, self.config) as db_interface:
            if not db_interface.is_firmware(uid):
                return False
        return True


@api.route(
    '/<string:search_id>',
    doc={
        'description': 'Get the results of a previously initiated binary search',
        'params': {'search_id': 'Search ID'}
    }
)
class RestBinarySearchGet(RestBinarySearchBase):

    @roles_accepted(*PRIVILEGES['pattern_search'])
    @api.doc(responses={200: 'Success', 400: 'Unknown search ID'})
    def get(self, search_id=None):
        '''
        Get the results of a previously initiated binary search
        The `search_id` is needed to fetch the corresponding search result
        The result of the search request can only be fetched once
        After this the search needs to be started again.
        '''

        if search_id is None:
            return error_message('The request is missing a search_id (.../binary_search/<search_id>).', self.URL)

        with ConnectTo(InterComFrontEndBinding, self.config) as intercom:
            result, _ = intercom.get_binary_search_result(search_id)

        if result is None:
            return error_message('The result is not ready yet or it has already been fetched', self.URL)

        return success_message({'binary_search_results': result}, self.URL)

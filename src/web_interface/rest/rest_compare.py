from contextlib import suppress

from flask import request
from flask_restx import Namespace, Resource, fields

from helperFunctions.database import ConnectTo
from helperFunctions.dataConversion import normalize_compare_id
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface, FactCompareException
from web_interface.rest.helper import convert_rest_request, error_message, success_message
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/compare', description='Issue compares and retrieve compare results')


compare_model = api.model('Compare Firmware', {
    'uid_list': fields.List(description='List of UIDs', cls_or_instance=fields.String, required=True),
    'redo': fields.Boolean(description='Redo', default=False)
})


class RestCompareBase(Resource):
    URL = '/rest/compare'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config = kwargs.get('config', None)


@api.route('', doc={'description': 'Initiate a comparison'})
class RestComparePut(RestCompareBase):

    @roles_accepted(*PRIVILEGES['compare'])
    @api.expect(compare_model)
    def put(self):
        '''
        Start a comparison
        For this sake a list of uids of the files, which should be compared, is needed
        The uid_list shall contain uids of already analysed FileObjects or Firmware objects
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


@api.route(
    '/<string:compare_id>',
    doc={
        'description': 'Retrieve compare results',
        'params': {'compare_id': 'Firmware UID'}
    }
)
class RestCompareGet(RestCompareBase):

    @roles_accepted(*PRIVILEGES['compare'])
    @api.doc(responses={200: 'Success', 400: 'Unknown file object'})
    def get(self, compare_id=None):
        '''
        Request results from a comparisons
        The result can be requested by providing a semicolon separated list of uids as compare_id
        The response will contain a json_document with the compare result, along with the fields status, timestamp,
        request_resource and request as meta data
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

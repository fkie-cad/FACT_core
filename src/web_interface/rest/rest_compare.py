from contextlib import suppress

from flask import request
from flask_restx import Namespace, fields

from helperFunctions.data_conversion import convert_compare_id_to_list, normalize_compare_id
from helperFunctions.database import ConnectTo
from helperFunctions.uid import is_uid
from intercom.front_end_binding import InterComFrontEndBinding
from storage.db_interface_compare import CompareDbInterface, FactCompareException
from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/compare', description='Start comparisons and retrieve results')


compare_model = api.model('Compare Firmware', {
    'uid_list': fields.List(description='List of UIDs', cls_or_instance=fields.String, required=True),
    'redo': fields.Boolean(description='Redo', default=False)
})


@api.route('', doc={'description': 'Initiate a comparison'})
class RestComparePut(RestResourceBase):
    URL = '/rest/compare'

    @roles_accepted(*PRIVILEGES['compare'])
    @api.expect(compare_model)
    def put(self):
        '''
        Start a comparison
        For this sake a list of uids of the files, which should be compared, is needed
        The `uid_list` must contain uids of already analysed FileObjects or Firmware objects
        '''
        data = self.validate_payload_data(compare_model)
        compare_id = normalize_compare_id(';'.join(data['uid_list']))

        with ConnectTo(CompareDbInterface, self.config) as db_compare_service:
            if db_compare_service.compare_result_is_in_db(compare_id) and not data['redo']:
                return error_message(
                    'Compare already exists. Use "redo" to force re-compare.',
                    self.URL, request_data=request.json, return_code=200
                )
            try:
                db_compare_service.check_objects_exist(compare_id)
            except FactCompareException as exception:
                return error_message(exception.get_message(), self.URL, request_data=request.json, return_code=404)

        with ConnectTo(InterComFrontEndBinding, self.config) as intercom:
            intercom.add_compare_task(compare_id, force=data['redo'])
        return success_message(
            {'message': 'Compare started. Please use GET to get the results.'},
            self.URL, request_data=request.json, return_code=202
        )


@api.route(
    '/<string:compare_id>',
    doc={
        'description': 'Retrieve comparison results',
        'params': {'compare_id': 'Firmware UID'}
    }
)
class RestCompareGet(RestResourceBase):
    URL = '/rest/compare'

    @roles_accepted(*PRIVILEGES['compare'])
    @api.doc(responses={200: 'Success', 400: 'Unknown comparison ID'})
    def get(self, compare_id):
        '''
        Request results from a comparisons
        The result can be requested by providing a semicolon separated list of uids as compare_id
        The response will contain a json_document with the comparison result, along with the fields status, timestamp,
        request_resource and request as meta data
        '''
        try:
            self._validate_compare_id(compare_id)
            compare_id = normalize_compare_id(compare_id)
        except (TypeError, ValueError) as error:
            return error_message(
                f'Compare ID must be of the form uid1;uid2(;uid3..): {error}',
                self.URL, request_data={'compare_id': compare_id}
            )

        with ConnectTo(CompareDbInterface, self.config) as db_compare_service:
            result = None
            with suppress(FactCompareException):
                if db_compare_service.compare_result_is_in_db(compare_id):
                    result = db_compare_service.get_compare_result(compare_id)
        if result:
            return success_message(result, self.URL, request_data={'compare_id': compare_id}, return_code=202)
        return error_message('Compare not found in database. Please use /rest/start_compare to start the compare.', self.URL, request_data={'compare_id': compare_id}, return_code=404)

    @staticmethod
    def _validate_compare_id(compare_id: str):
        valid_chars = '0123456789abcdef_;'
        if not all(char in valid_chars for char in compare_id):
            raise ValueError(f'Compare ID {compare_id} contains invalid chars')
        uids = convert_compare_id_to_list(compare_id)
        if not all(is_uid(uid) for uid in uids):
            raise TypeError(f'Compare ID {compare_id} contains invalid UIDs')

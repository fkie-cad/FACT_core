from flask import request
from flask_restx import Namespace, fields

from helperFunctions.data_conversion import convert_comparison_id_to_list, normalize_comparison_id
from helperFunctions.database import get_shared_session
from helperFunctions.uid import is_uid
from web_interface.rest.helper import error_message, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/compare', description='Start comparisons and retrieve results')


compare_model = api.model(
    'Compare Firmware',
    {
        'uid_list': fields.List(description='List of UIDs', cls_or_instance=fields.String, required=True),
        'redo': fields.Boolean(description='Redo', default=False),
    },
)


@api.route('', doc={'description': 'Initiate a comparison'})
class RestComparePut(RestResourceBase):
    URL = '/rest/compare'

    @roles_accepted(*PRIVILEGES['compare'])
    @api.expect(compare_model)
    def put(self):
        """
        Start a comparison
        For this sake a list of UIDs of the files, which should be compared, is needed
        The `uid_list` must contain UIDs of already analysed FileObjects or Firmware objects
        """
        data = self.validate_payload_data(compare_model)
        comparison_id = normalize_comparison_id(';'.join(data['uid_list']))

        with get_shared_session(self.db.comparison) as comparison_db:
            if comparison_db.comparison_exists(comparison_id) and not data['redo']:
                return error_message(
                    'Comparison already exists. Use "redo" to force re-compare.',
                    self.URL,
                    request_data=request.json,
                    return_code=200,
                )

            if not comparison_db.objects_exist(comparison_id):
                missing_uids = ', '.join(
                    uid for uid in convert_comparison_id_to_list(comparison_id) if not comparison_db.exists(uid)
                )
                return error_message(
                    f'Some objects are not found in the database: {missing_uids}',
                    self.URL,
                    request_data=request.json,
                    return_code=404,
                )

        self.intercom.add_comparison_task(comparison_id, force=data['redo'])
        return success_message(
            {'message': 'Comparison started. Please use GET to get the results.'},
            self.URL,
            request_data=request.json,
            return_code=202,
        )


@api.route(
    '/<string:comparison_id>',
    doc={'description': 'Retrieve comparison results', 'params': {'comparison_id': 'Firmware UID'}},
)
class RestCompareGet(RestResourceBase):
    URL = '/rest/compare'

    @roles_accepted(*PRIVILEGES['compare'])
    @api.doc(responses={200: 'Success', 400: 'Unknown comparison ID'})
    def get(self, comparison_id):
        """
        Request results from a comparison
        The result can be requested by providing a semicolon separated list of UIDs as comparison_id
        The response will contain a json_document with the comparison result, along with the fields status, timestamp,
        request_resource and request as metadata
        """
        try:
            self._validate_comparison_id(comparison_id)
            comparison_id = normalize_comparison_id(comparison_id)
        except (TypeError, ValueError) as error:
            return error_message(
                f'Comparison ID must be of the form uid1;uid2(;uid3..): {error}',
                self.URL,
                request_data={'comparison_id': comparison_id},
            )

        result = None
        with get_shared_session(self.db.comparison) as comparison_db:
            if comparison_db.comparison_exists(comparison_id):
                result = comparison_db.get_comparison_result(comparison_id)
        if result:
            return success_message(result, self.URL, request_data={'comparison_id': comparison_id}, return_code=202)
        return error_message(
            'Comparison not found in database. Please use PUT /rest/compare to start the comparison.',
            self.URL,
            request_data={'comparison_id': comparison_id},
            return_code=404,
        )

    @staticmethod
    def _validate_comparison_id(comparison_id: str):
        valid_chars = '0123456789abcdef_;'
        if not all(char in valid_chars for char in comparison_id):
            raise ValueError(f'Comparison ID {comparison_id} contains invalid chars')
        uids = convert_comparison_id_to_list(comparison_id)
        if not all(is_uid(uid) for uid in uids):
            raise TypeError(f'Comparison ID {comparison_id} contains invalid UIDs')

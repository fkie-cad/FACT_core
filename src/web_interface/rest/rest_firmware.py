import binascii
import logging
from base64 import standard_b64decode

from flask import request
from flask_restx import Namespace, fields
from flask_restx.fields import MarshallingError

from helperFunctions.database import ConnectTo
from helperFunctions.object_conversion import create_meta_dict
from helperFunctions.task_conversion import convert_analysis_task_to_fw_obj
from objects.firmware import Firmware
from storage.db_interface_base import DbInterfaceError
from web_interface.rest.helper import (
    error_message, get_boolean_from_request, get_paging, get_query, get_update, success_message
)
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/firmware', description='Query the firmware database or upload a firmware')


firmware_model = api.model('Upload Firmware', {
    'device_name': fields.String(description='Device Name', required=True),
    'device_part': fields.String(description='Device Part', required=True),
    'device_class': fields.String(description='Device Class', required=True),
    'file_name':  fields.String(description='File Name', required=True),
    'version':  fields.String(description='Version', required=True),
    'vendor':  fields.String(description='Vendor', required=True),
    'release_date':  fields.Date(dt_format='iso8601', description='Release Date (ISO 8601)', default='1970-01-01'),
    'tags':  fields.String(description='Tags'),
    'requested_analysis_systems': fields.List(description='Selected Analysis Systems', cls_or_instance=fields.String),
    'binary': fields.String(description='Base64 String Representing the Raw Binary', required=True),
})


@api.route('', doc={'description': ''})
class RestFirmwareGetWithoutUid(RestResourceBase):
    URL = '/rest/firmware'

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @api.doc(
        responses={200: 'Success', 400: 'Unknown file object'},
        params={
            'offset': {'description': 'offset of results (paging)', 'in': 'query', 'type': 'int'},
            'limit': {'description': 'number of results (paging)', 'in': 'query', 'type': 'int'},
            'query': {'description': 'MongoDB style query', 'in': 'query', 'type': 'dict'},
            'recursive': {
                'description': 'Query for parent firmware of matching objects (requires query)',
                'in': 'query', 'type': 'boolean', 'default': 'false',
            },
            'inverted': {
                'description': 'Query for parent firmware that does not include the matching objects (Requires query '
                               'and recursive)',
                'in': 'query', 'type': 'boolean', 'default': 'false',
            },
        }
    )
    def get(self):
        '''
        Browse the firmware database
        List all available firmware in the database
        '''
        try:
            query, recursive, inverted, offset, limit = self._get_parameters_from_request(request.args)
        except ValueError as value_error:
            request_data = {k: request.args.get(k) for k in ['query', 'limit', 'offset', 'recursive', 'inverted']}
            return error_message(str(value_error), self.URL, request_data=request_data)

        parameters = dict(offset=offset, limit=limit, query=query, recursive=recursive, inverted=inverted)
        try:
            uids = self.db.frontend.rest_get_firmware_uids(**parameters)
            return success_message(dict(uids=uids), self.URL, parameters)
        except DbInterfaceError:
            return error_message('Unknown exception on request', self.URL, parameters)

    @staticmethod
    def _get_parameters_from_request(request_parameters):
        query = get_query(request_parameters)
        recursive = get_boolean_from_request(request_parameters, 'recursive')
        inverted = get_boolean_from_request(request_parameters, 'inverted')
        offset, limit = get_paging(request.args)
        if recursive and not query:
            raise ValueError('Recursive search is only permissible with non-empty query')
        if inverted and not recursive:
            raise ValueError('Inverted flag can only be used with recursive')
        return query, recursive, inverted, offset, limit

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @api.expect(firmware_model)
    def put(self):
        '''
        Upload a firmware
        The HTTP body must contain a json document of the structure shown below
        Important: The binary has to be a base64 string representing the raw binary you want to submit
        '''
        try:
            data = self.validate_payload_data(firmware_model)
        except MarshallingError as error:
            logging.error(f'REST|firmware|PUT: Error in payload data: {error}')
            return error_message(str(error), self.URL)
        result = self._process_data(data)
        if 'error_message' in result:
            logging.warning('Submission not according to API guidelines! (data could not be parsed)')
            return error_message(result['error_message'], self.URL, request_data=data)

        logging.debug('Upload Successful!')
        return success_message(result, self.URL, request_data=data)

    def _process_data(self, data):
        try:
            data['binary'] = standard_b64decode(data['binary'])
        except binascii.Error:
            return dict(error_message='Could not parse binary (must be valid base64!)')
        firmware_object = convert_analysis_task_to_fw_obj(data)
        with ConnectTo(self.intercom, self.config) as intercom:
            intercom.add_analysis_task(firmware_object)
        data.pop('binary')

        return dict(uid=firmware_object.uid)


@api.route('/<string:uid>', doc={'description': '', 'params': {'uid': 'Firmware UID'}})
class RestFirmwareGetWithUid(RestResourceBase):
    URL = '/rest/firmware'

    @roles_accepted(*PRIVILEGES['view_analysis'])
    @api.doc(
        responses={200: 'Success', 400: 'Unknown UID'},
        params={'summary': {'description': 'include summary in result', 'in': 'query', 'type': 'boolean', 'default': 'false'}}
    )
    def get(self, uid):
        '''
        Request a specific firmware
        Get the analysis results of a specific firmware by providing the corresponding uid
        '''
        summary = get_boolean_from_request(request.args, 'summary')
        if summary:
            firmware = self.db.frontend.get_complete_object_including_all_summaries(uid)
        else:
            firmware = self.db.frontend.get_object(uid)
        if not firmware or not isinstance(firmware, Firmware):
            return error_message(f'No firmware with UID {uid} found', self.URL, dict(uid=uid))

        fitted_firmware = self._fit_firmware(firmware)
        return success_message(dict(firmware=fitted_firmware), self.URL, request_data=dict(uid=uid))

    @staticmethod
    def _fit_firmware(firmware):
        meta = create_meta_dict(firmware)
        analysis = firmware.processed_analysis
        return dict(meta_data=meta, analysis=analysis)

    @roles_accepted(*PRIVILEGES['submit_analysis'])
    @api.expect(firmware_model)
    def put(self, uid):
        '''
        Update existing firmware analysis
        You can use this endpoint to update a firmware analysis which is already existing
        '''
        try:
            update = get_update(request.args)
        except ValueError as value_error:
            return error_message(str(value_error), self.URL, request_data={'uid': uid})
        return self._update_analysis(uid, update)

    def _update_analysis(self, uid, update):
        firmware = self.db.frontend.get_object(uid)
        if not firmware:
            return error_message(f'No firmware with UID {uid} found', self.URL, dict(uid=uid))

        unpack = 'unpacker' in update
        while 'unpacker' in update:
            update.remove('unpacker')

        firmware.scheduled_analysis = update

        with ConnectTo(self.intercom, self.config) as intercom:
            supported_plugins = intercom.get_available_analysis_plugins().keys()
            for item in update:
                if item not in supported_plugins:
                    return error_message(f'Unknown analysis system \'{item}\'', self.URL, dict(uid=uid, update=update))
            intercom.add_re_analyze_task(firmware, unpack)

        if unpack:
            update.append('unpacker')
        return success_message({}, self.URL, dict(uid=uid, update=update))

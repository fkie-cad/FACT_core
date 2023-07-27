from base64 import standard_b64encode

from flask import request
from flask_restx import Namespace

from helperFunctions.database import ConnectTo
from helperFunctions.hash import get_sha256
from web_interface.rest.helper import error_message, get_boolean_from_request, success_message
from web_interface.rest.rest_resource_base import RestResourceBase
from web_interface.security.decorator import roles_accepted
from web_interface.security.privileges import PRIVILEGES

api = Namespace('rest/binary', description='Request the binary of a given firmware or file object')


@api.route(
    '/<string:uid>',
    doc={
        'description': 'Request a binary by providing the uid of the corresponding object',
        'params': {
            'uid': 'Firmware UID',
            'tar': {
                'description': 'Get tar.gz packed contents of target',
                'in': 'query',
                'type': 'boolean',
                'default': 'false',
            },
        },
    },
)
class RestBinary(RestResourceBase):
    URL = '/rest/binary'

    @roles_accepted(*PRIVILEGES['download'])
    @api.doc(responses={200: 'Success', 404: 'Unknown UID'})
    def get(self, uid):
        '''
        Request a binary
        The uid of the file_object in question has to be given in the url
        Alternatively the tar parameter can be used to get the target archive as its content repacked into a .tar.gz.
        The return format will be {"binary": b64_encoded_binary_or_tar_gz, "file_name": file_name}
        '''
        if not self.db.frontend.exists(uid):
            return error_message(
                f'No firmware with UID {uid} found in database', self.URL, request_data={'uid': uid}, return_code=404
            )

        try:
            tar_flag = get_boolean_from_request(request.args, 'tar')
        except ValueError as value_error:
            return error_message(str(value_error), self.URL, request_data={'uid': uid, 'tar': request.args.get('tar')})

        with ConnectTo(self.intercom) as intercom:
            if not tar_flag:
                binary, file_name = intercom.get_binary_and_filename(uid)
            else:
                binary, file_name = intercom.get_repacked_binary_and_file_name(uid)

        response = {'binary': standard_b64encode(binary).decode(), 'file_name': file_name, 'SHA256': get_sha256(binary)}
        return success_message(response, self.URL, request_data={'uid': uid, 'tar': tar_flag})

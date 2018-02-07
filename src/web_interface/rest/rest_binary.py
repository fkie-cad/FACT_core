from base64 import standard_b64encode

from flask_restful import Resource

from helperFunctions.hash import get_sha256
from helperFunctions.rest import success_message, error_message
from helperFunctions.web_interface import ConnectTo
from intercom.front_end_binding import InterComFrontEndBinding
from security_switch import roles_accepted, PRIVILEGES
from storage.db_interface_frontend import FrontEndDbInterface


class RestBinary(Resource):
    URL = '/rest/binary'

    def __init__(self, **kwargs):
        self.config = kwargs.get('config', None)

    @roles_accepted(PRIVILEGES['download'])
    def get(self, uid):
        '''
        The uid of the file_object in question has to be given in the url
        The return format will be {"binary": b64_encoded_binary, "file_name": file_name}
        '''
        with ConnectTo(FrontEndDbInterface, self.config) as db_service:
            existence = db_service.existence_quick_check(uid)
        if not existence:
            return error_message('No firmware with UID {} found in database'.format(uid), self.URL, request_data={'uid': uid}, return_code=404)

        with ConnectTo(InterComFrontEndBinding, self.config) as intercom:
            binary, file_name = intercom.get_binary_and_filename(uid)

        response = {
            'binary': standard_b64encode(binary).decode(),
            'file_name': file_name,
            'SHA256': get_sha256(binary)
        }
        return success_message(response, self.URL, request_data={'uid': uid})
